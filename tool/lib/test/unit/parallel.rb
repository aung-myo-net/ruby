# frozen_string_literal: true
$LOAD_PATH.unshift "#{__dir__}/../.."
require_relative '../../test/unit'

require_relative '../../profile_test_all' if ENV.key?('RUBY_TEST_ALL_PROFILE')
require_relative '../../tracepointchecker'
require_relative '../../zombie_hunter'
require_relative '../../iseq_loader_checker'
require_relative '../../gc_checker'

module Test
  module Unit
    # Worker sub-process
    class Worker < Runner # :nodoc:
      class << self
        undef autorun
      end

      undef _run_suite
      undef _run_suites
      undef run

      private

      def worker_process?
        true
      end

      def increment_io(orig) # :nodoc:
        *rest, io = 32.times.inject([orig.dup]){|ios, | ios << ios.last.dup }
        rest.each(&:close)
        io
      end

      def _run_suites(suites, type) # :nodoc:
        suites.each do |suite|
          _run_suite(suite, type)
        end
      end

      def _start_method(inst)
        _report "start", Marshal.dump([inst.class.name, inst.__name__, @last_test_assertions])
      end

      def _run_suite(suite, type) # :nodoc:
        @partial_report = []
        @last_test_assertions = 0
        orig_testout = Test::Unit::Runner.output
        i,o = IO.pipe

        Test::Unit::Runner.output = o
        orig_stdin, orig_stdout = $stdin, $stdout

        th = Thread.new do
          readbuf = []
          begin
            # buf here is '.', 'S', 'E', 'F' unless in verbose mode
            while buf = (readbuf.shift || (@verbose ? i.gets : i.readpartial(1024)))
              outbuf = buf
              # We want outbuf to be 1 character so that if it's 'E' or 'F',
              # we send the error message with it. See `_report`
              if outbuf =~ /\A[EF]/ && !@verbose && buf.size > 1 && @report.size > 0
                readbuf.concat buf[1..-1].chars
                outbuf = buf[0]
              end
              _report "p", outbuf unless @need_exit
            end
          rescue IOError
          end
        end

        @errors = 0
        @failures = 0
        @skips = 0

        begin
          result = orig_run_suite(suite, type)
        rescue Interrupt
          # Using a terminal, interrupt signal by ctrl-c is sent to all processes in
          # foreground process group, so even child processes get the signal.
          # Send "done" to parent with the results we collected so far.
          @need_exit = true
          result = [@suite_test_count, @suite_assertion_count]
        end

        Test::Unit::Runner.output = orig_testout
        $stdin = orig_stdin
        $stdout = orig_stdout

        o.close
        begin
          th.join
        rescue IOError
          raise unless /stream closed|closed stream/ =~ $!.message
        end
        i.close

        result << @partial_report
        @partial_report = nil
        result << [@errors,@failures,@skips]
        result << ($: - @old_loadpath)
        result << suite.name

        _report "done", Marshal.dump(result)
        return result
      ensure
        Test::Unit::Runner.output = orig_stdout
        $stdin = orig_stdin if orig_stdin
        $stdout = orig_stdout if orig_stdout
        o.close if o && !o.closed?
        i.close if i && !i.closed?
      end

      # We namespace the reporting with "_R_: " because other messages could
      # be sent to $stdout that aren't through this function, and they will be
      # received by the parent process. We need to be able to distinguish these
      # other messages from worker reports.
      def _report(res, *args) # :nodoc:
        if res == "p" && args[0] && args[0] =~ /\A[EF]\z/ && @report.size > 0
          args << @report.shift # the error message
          @stdout.write("_R_: #{res} #{args[0]} #{args[1..-1].pack("m0")}\n")
          return true
        end
        @stdout.write(args.empty? ? "_R_: #{res}\n" : "_R_: #{res} #{args.pack("m0")}\n")
        true
      rescue Errno::EPIPE
      rescue TypeError => e
        abort("#{e.inspect} in _report(#{res.inspect}, #{args.inspect})\n#{e.backtrace.join("\n")}")
      end

      public

      # entire worker run, runs multiple suites (files)
      def run(args = []) # :nodoc:
        process_args args
        @@stop_auto_run = true
        @opts = @options.dup
        @need_exit = false
        $LOAD_PATH.unshift(DEFAULT_TEST_DIR) unless $:.include?(DEFAULT_TEST_DIR)

        @old_loadpath = []
        begin
          begin
            @stdout = increment_io(STDOUT)
            @stdin = increment_io(STDIN)
          rescue
            exit 2
          end
          exit 2 unless @stdout && @stdin

          @stdout.sync = true
          _report "ready!"
          while buf = @stdin.gets
            case buf.chomp
            when /^loadpath (.+?)$/
              @old_loadpath = $:.dup
              $:.push(*Marshal.load($1.unpack1("m").force_encoding("ASCII-8BIT"))).uniq!
            when /^run (.+?) (.+?)$/
              suite_file = $1
              suite_type = $2
              _report "okay"

              @options = @opts.dup
              old_suites = Test::Unit::TestCase.test_suites

              begin
                require File.realpath(suite_file)
              rescue LoadError => e
                _report "after", Marshal.dump([suite_file, ProxyError.new(e)])
                _report "ready"
                next
              end
              # NOTE: this array can be empty if the file defined no class, like if there
              # is a guard around the definition of the class that was not met
              this_suite_ary = Test::Unit::TestCase.test_suites - old_suites
              _run_suites this_suite_ary, suite_type.to_sym

              if @need_exit
                _report "bye"
                exit
              else
                _report "ready"
              end
            when /^quit$/
              _report "bye"
              exit
            end
          end
        rescue Interrupt, SystemExit # do nothing
        rescue Exception => e
          trace = e.backtrace || ['unknown method']
          err = ["#{trace.shift}: #{e.message} (#{e.class})"] + trace.map{|t| "\t" + t }

          # The exception occured as a result of the interrupt
          if @need_exit
            _report "bye"
            exit
          end

          if @stdout
            _report "bye", Marshal.dump(err.join("\n"))
          else
            raise "failed to report a failure due to lack of @stdout"
          end
          exit
        ensure
          @stdin.close if @stdin
          @stdout.close if @stdout
        end
      end

      def puke(klass, meth, e) # :nodoc:
        if e.is_a?(Test::Unit::PendedError)
          new_e = Test::Unit::PendedError.new(e.message)
          new_e.set_backtrace(e.backtrace)
          e = new_e
        end
        @partial_report << [klass.name, meth, e.is_a?(Test::Unit::AssertionFailedError) ? e : ProxyError.new(e)]
        super # populate @report, @errors, @failures, etc.
      end

      def record(suite, method, assertions, time, error) # :nodoc:
        return unless recording?
        case error
        when nil
        when Test::Unit::AssertionFailedError, Test::Unit::PendedError
          case error.cause
          when nil, Test::Unit::AssertionFailedError, Test::Unit::PendedError
          else
            bt = error.backtrace
            error = error.class.new(error.message)
            error.set_backtrace(bt)
          end
        else
          error = ProxyError.new(error)
        end
        _report "record", Marshal.dump([suite.name, method, assertions, time, error])
      end
    end
  end
end

if $0 == __FILE__
  module Test
    module Unit
      class TestCase # :nodoc: all
        undef on_parallel_worker?
        def on_parallel_worker?
          true
        end
        def self.on_parallel_worker?
          true
        end
      end
    end
  end
  require 'rubygems'
  Test::Unit::Worker.new.run(ARGV)
end

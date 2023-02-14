# frozen_string_literal: true

# Enable deprecation warnings for test-all, so deprecated methods/constants/functions are dealt with early.
Warning[:deprecated] = true

if ENV['BACKTRACE_FOR_DEPRECATION_WARNINGS']
  Warning.extend Module.new {
    def warn(message, category: nil, **kwargs)
      if category == :deprecated and $stderr.respond_to?(:puts)
        $stderr.puts nil, message, caller, nil
      else
        super
      end
    end
  }
end

require_relative '../envutil'
require_relative '../colorize'
require_relative '../leakchecker'
require_relative '../test/unit/testcase'
require 'optparse'

# See Test::Unit
module Test

  class << self
    ##
    # Filter object for backtraces.
    attr_accessor :backtrace_filter
  end

  class BacktraceFilter # :nodoc:
    def filter bt
      return ["No backtrace"] unless bt

      new_bt = []
      pattern = %r[/(?:lib\/test/|core_assertions\.rb:)]

      unless $DEBUG then
        bt.each do |line|
          break if pattern.match?(line)
          new_bt << line
        end

        new_bt = bt.reject { |line| pattern.match?(line) } if new_bt.empty?
        new_bt = bt.dup if new_bt.empty?
      else
        new_bt = bt.dup
      end

      new_bt
    end
  end

  self.backtrace_filter = BacktraceFilter.new

  def self.filter_backtrace bt # :nodoc:
    backtrace_filter.filter bt
  end

  ##
  # Test::Unit is an implementation of the xUnit testing framework for Ruby.
  module Unit
    DEFAULT_TEST_DIR = File.expand_path(__dir__ + "../../../../test") # :nodoc:
    private_constant :DEFAULT_TEST_DIR
    ##
    # Assertion base class

    class AssertionFailedError < Exception; end

    ##
    # Assertion raised when skipping a test

    class PendedError < AssertionFailedError; end

    module Order # :nodoc: all
      class NoSort
        def initialize(seed)
        end

        def sort_by_name(list)
          list
        end

        alias sort_by_string sort_by_name

        def group(list)
          list
        end
      end

      module MJITFirst
        def group(list)
          # MJIT first
          mjit, others = list.partition {|e| /test_mjit/ =~ e}
          mjit + others
        end
      end

      class Alpha < NoSort
        #include MJITFirst

        def sort_by_name(list)
          list.sort_by(&:name)
        end

        def sort_by_string(list)
          list.sort
        end

      end

      # shuffle test suites based on CRC32 of their names
      Shuffle = Struct.new(:seed, :salt) do # :nodoc: all
        #include MJITFirst

        def initialize(seed)
          self.class::CRC_TBL ||= (0..255).map {|i|
            (0..7).inject(i) {|c,| (c & 1 == 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1) }
          }.freeze

          salt = [seed].pack("V").unpack1("H*")
          super(seed, "\n#{salt}".freeze).freeze
        end

        def sort_by_name(list)
          list.sort_by {|e| randomize_key(e.name)}
        end

        def sort_by_string(list)
          list.sort_by {|e| randomize_key(e)}
        end

        def group(list)
          list
        end

        private

        def crc32(str, crc32 = 0xffffffff)
          crc_tbl = self.class::CRC_TBL
          str.each_byte do |data|
            crc32 = crc_tbl[(crc32 ^ data) & 0xff] ^ (crc32 >> 8)
          end
          crc32
        end

        def randomize_key(name)
          crc32(salt, crc32(name)) ^ 0xffffffff
        end
      end

      Types = {
        random: Shuffle,
        alpha: Alpha,
        sorted: Alpha,
        nosort: NoSort,
      }
      Types.default_proc = proc {|_, order|
        raise "Unknown test_order: #{order.inspect}"
      }
    end

    module RunCount # :nodoc: all
      @@run_count = 0

      def self.have_run?
        @@run_count.nonzero?
      end

      def run_once
        return if have_run?
        return if $! # don't run if there was an exception
        yield
      end

      def run(*)
        @@run_count += 1
        super
      end

      module_function :run_once
    end

    module Options # :nodoc: all
      attr_reader :option_parser, :verbose
      attr_writer :default_dir

      def initialize(*, &block)
        @init_hook = block
        @options = nil
        @run_options = nil
        @help = nil
        @order = nil
        @verbose = false
        @default_dir = nil
        @option_parser = OptionParser.new
        super(&nil)
      end

      def process_args(args = [])
        return @options if @options
        orig_args = args.dup
        options = {}
        setup_options(@option_parser, options)
        @option_parser.parse!(args)
        orig_args -= args
        args = @init_hook.call(self, args, options) if @init_hook
        non_options(args, options)
        @run_options = orig_args

        order = options[:test_order]
        if seed = options[:seed]
          order ||= :random
        elsif (order ||= :random) == :random
          seed = options[:seed] = rand(0x10000)
          orig_args.unshift "--seed=#{seed}"
        end
        Test::Unit::TestCase.test_order = order if order
        order = Test::Unit::TestCase.test_order
        @order = Test::Unit::Order::Types[order].new(seed)

        @help = "\n" + orig_args.map { |s|
          "  " + (s =~ /[\s|&<>$()]/ ? s.inspect : s)
        }.join("\n")

        if @orig_files.any?
          custom_basedirs = options[:base_directories]
          custom_basedirs = nil if custom_basedirs == [@default_dir]
          unless custom_basedirs && @orig_files == [@default_dir]
            @help << "\n  #{@orig_files.inspect}\n"
          end
        end

        @options = options # first time @options is set
      end

      private

      def setup_options(opts, options)
        opts.separator 'test-unit options:'

        opts.on '-h', '--help', 'Display this help.' do
          puts opts
          exit
        end

        opts.on '-s', '--seed SEED', Integer, "Sets random seed" do |m|
          options[:seed] = m.to_i
        end

        opts.on '-v', '--verbose', "Verbose. Show progress processing files." do
          options[:verbose] = true
          @verbose = options[:verbose]
        end

        opts.on '-n', '--name PATTERN', "Filter test method names on pattern: /REGEXP/, !/REGEXP/ or STRING" do |a|
          (options[:test_name_filter] ||= []) << a
        end

        orders = Test::Unit::Order::Types.keys
        opts.on "--test-order=#{orders.join('|')}", orders do |a|
          options[:test_order] = a
        end
      end

      # Change options[:test_name_filter] from Array of strings/regexps to single regexp
      def non_options(files, options)
        filter = options[:test_name_filter]
        if filter
          pos_pat = /\A\/(.*)\/\z/
          neg_pat = /\A!\/(.*)\/\z/
          negative, positive = filter.partition {|s| neg_pat =~ s}
          if positive.empty?
            filter = nil
          elsif negative.empty? and positive.size == 1 and pos_pat !~ positive[0]
            filter = positive[0]
            unless /\A[A-Z]\w*(?:::[A-Z]\w*)*#/ =~ filter
              filter = /##{Regexp.quote(filter)}\z/
            end
          else
            filter = Regexp.union(*positive.map! {|s| Regexp.new(s[pos_pat, 1] || "\\A#{Regexp.quote(s)}\\z")})
          end
          unless negative.empty?
            negative = Regexp.union(*negative.map! {|s| Regexp.new(s[neg_pat, 1])})
            filter = /\A(?=.*#{filter})(?!.*#{negative})/
          end
          options[:test_name_filter] = filter
        end
        true
      end
    end

    module Parallel # :nodoc: all
      # More ivars for parallel test state are set in _run_parallel
      def initialize(*, &blk)
        @jobserver = nil
        @worker_timeout = nil
        @interrupt = nil
        @files = nil
        super
      end

      def process_args(args = [])
        return @options if @options
        options = super
        if options[:parallel]
          @files = args
        end
        options
      end

      def status(*args)
        result = super
        raise @interrupt if @interrupt
        result
      end

      private

      def non_options(files, options)
        return super(files, options) if worker_process?
        makeflags = ENV.delete("MAKEFLAGS")
        if !options[:parallel] and
          /(?:\A|\s)--jobserver-(?:auth|fds)=(?:(\d+),(\d+)|fifo:((?:\\.|\S)+))/ =~ makeflags
          begin
            if fifo = $3
              fifo.gsub!(/\\(?=.)/, '')
              r = File.open(fifo, IO::RDONLY|IO::NONBLOCK|IO::BINARY)
              w = File.open(fifo, IO::WRONLY|IO::NONBLOCK|IO::BINARY)
            else
              r = IO.for_fd($1.to_i(10), "rb", autoclose: false)
              w = IO.for_fd($2.to_i(10), "wb", autoclose: false)
            end
          rescue
            r.close if r
            nil
          else
            r.close_on_exec = true
            w.close_on_exec = true
            @jobserver = [r, w]
            options[:parallel] ||= 1
          end
        end
        @worker_timeout = EnvUtil.apply_timeout_scale(options[:worker_timeout] || 180)
        super
      end

      def worker_process?
        false
      end

      def setup_options(opts, options)
        super

        opts.separator "parallel test options:"

        options[:retry] = true

        opts.on '-j N', '--jobs N', /\A(t)?(\d+)\z/, "Allow run tests with N jobs at once" do |_, t, a|
          options[:testing] = true & t # For testing
          options[:parallel] = a.to_i
        end

        opts.on '--worker-timeout=N', Integer, "Timeout workers not responding in N seconds" do |a|
          options[:worker_timeout] = a
        end

        opts.on '--separate', "Restart job process after one testcase has done" do
          options[:parallel] ||= 1
          options[:separate] = true
        end

        opts.on '--retry', "Retry running testcase when --jobs specified" do
          options[:retry] = true
        end

        opts.on '--no-retry', "Disable --retry" do
          options[:retry] = false
        end

        opts.on '--ruby VAL', "Path to ruby which is used at -j option" do |a|
          options[:ruby] = a.split(/ /).reject(&:empty?)
        end

        opts.on '--timetable-data=FILE', "Path to timetable data" do |a|
          options[:timetable_data] = a
        end
      end

      def need_records?
        @options[:timetable_data] || super
      end

      # Set $VERBOSE or $DEBUG manually when debugging
      def debug
        if $VERBOSE || $DEBUG
          $stderr.puts yield
        end
      end

      class Worker # :nodoc: all
        def self.launch(ruby,args=[])
          scale = EnvUtil.timeout_scale
          io = IO.popen([*ruby, "-W1",
                        "#{__dir__}/unit/parallel.rb",
                        *("--timeout-scale=#{scale}" if scale),
                        *args, { err: [:child, :out] }], "rb+")
          new(io, io.pid, :waiting)
        end

        attr_reader :num, :io, :pid, :real_file, :quit_called, :response_at
        attr_accessor :start_time, :current, :status

        @@worker_number = 0

        def initialize(io, pid, status)
          @num = (@@worker_number += 1)
          @io = io
          @pid = pid
          @status = status
          @file = nil
          @real_file = nil
          @loadpath = []
          @hooks = {}
          @quit_called = false
          @need_quit = false
          @response_at = nil
          @start_time = nil
          @current = nil
        end

        def name
          "Worker #{@num}"
        end

        def puts(*args)
          @io.puts(*args)
        end

        # Communicates with worker process to run a test file
        def run(task,type)
          @file = File.basename(task, ".rb")
          @real_file = task
          begin
            puts "loadpath #{[Marshal.dump($:-@loadpath)].pack("m0")}"
            @loadpath = $:.dup
            puts "run #{task} #{type}"
            @status = :prepare
            @start_time = Time.now
            @response_at = @start_time
          rescue Errno::EPIPE
            died
          rescue IOError
            raise unless /stream closed|closed stream/ =~ $!.message
            died
          end
        end

        def hook(id,&block)
          @hooks[id] ||= []
          @hooks[id] << block
          self
        end

        def read
          res = (@status == :quit) ? @io.read : @io.gets
          @response_at = Time.now
          res && res.chomp
        end

        def close
          @io.close unless @io.closed?
          self
        rescue IOError
        end

        def quit
          return if @io.closed?
          @quit_called = true
          @io.puts "quit"
        rescue Errno::EPIPE => e
          warn "#{@pid}:#{@status.to_s.ljust(7)}:#{@file}: #{e.message}"
        end

        # TODO
        def quit_and_report
          return if @io.closed?
          @quit_called = true
          @io.puts "quit"
        rescue Errno::EPIPE => e
          warn "#{@pid}:#{@status.to_s.ljust(7)}:#{@file}: #{e.message}"
        end

        def kill
          Process.kill(:KILL, @pid)
        rescue Errno::ESRCH
        end

        def died(*additional)
          @status = :quit
          @io.close
          status = $?
          if status and status.signaled?
            additional[0] ||= SignalException.new(status.termsig)
          end

          call_hook(:dead,*additional)
        end

        def to_s
          if @file and @status != :ready
            "#{@pid}=#{@file}"
          else
            "#{@pid}:#{@status.to_s.ljust(7)}"
          end
        end

        private

        def call_hook(id,*additional)
          @hooks[id] ||= []
          @hooks[id].each{|hook| hook[self,additional] }
          self
        end
      end # Worker

      def flush_job_tokens
        if @jobserver
          r, w = @jobserver.shift(2)
          @jobserver = nil
          w << @job_tokens.slice!(0..-1)
          r.close
          w.close
        end
      end

      def after_worker_down(worker, e=nil, c=false)
        return unless @options[:parallel]
        return if @interrupt
        flush_job_tokens
        warn e if e
        real_file = worker.real_file and warn "running file: #{real_file}"
        @need_quit = true
        warn ""
        warn "A test worker crashed. It might be an interpreter bug or"
        warn "a bug in test/unit/parallel.rb. Try again without the -j"
        warn "option."
        warn ""
        if File.exist?('core')
          require 'fileutils'
          require 'time'
          Dir.glob('/tmp/test-unit-core.*').each do |f|
            if Time.now - File.mtime(f) > 7 * 24 * 60 * 60 # 7 days
              warn "Deleting an old core file: #{f}"
              FileUtils.rm(f)
            end
          end
          core_path = "/tmp/test-unit-core.#{Time.now.utc.iso8601}"
          warn "A core file is found. Saving it at: #{core_path.dump}"
          FileUtils.mv('core', core_path)
          cmd = ['gdb', RbConfig.ruby, '-c', core_path, '-ex', 'bt', '-batch']
          p cmd # debugging why it's not working
          system(*cmd)
        end
        STDERR.flush
        exit c
      end

      def after_worker_quit(worker)
        return unless @options[:parallel]
        return if @interrupt
        worker.close
        if @jobserver and (token = @job_tokens.slice!(0))
          @jobserver[1] << token
        end
        @workers.delete(worker)
        @dead_workers << worker
        @ios = @workers.map(&:io)
      end

      def launch_worker
        begin
          worker = Worker.launch(@options[:ruby], @run_options)
        rescue => e
          abort "ERROR: Failed to launch job process - #{e.class}: #{e.message}"
        end
        worker.hook(:dead) do |w,info|
          after_worker_quit w
          after_worker_down w, *info if !info.empty? && !worker.quit_called
        end
        @workers << worker
        @ios << worker.io
        @workers_hash[worker.io] = worker
        worker
      end

      def delete_worker(worker)
        @workers_hash.delete worker.io
        @workers.delete worker
        @ios.delete worker.io
      end

      def quit_workers(&cond)
        return if @workers.empty?
        closed = [] if cond
        @workers.reject! do |worker|
          next unless cond&.call(worker)
          begin
            Timeout.timeout(1) do
              worker.quit_and_report
            end
          rescue Errno::EPIPE
          rescue Timeout::Error
            debug { "Quit timeout expired for worker #{worker.num} (#{worker.pid})" }
          end
          closed&.push worker
          begin
            Timeout.timeout(0.2) do
              worker.close
            end
          rescue Timeout::Error
            debug { "Killing worker #{worker.num} (#{worker.pid}) after close timeout expired" }
            worker.kill
            retry
          end
          @ios.delete worker.io
        end

        return if (closed ||= @workers).empty?
        pids = closed.map(&:pid)
        begin
          Timeout.timeout(0.2 * closed.size) do
            Process.waitall
          end
        rescue Timeout::Error
          if pids
            debug { "Killing worker processes #{pids.map(&:to_s).join(',')} after timeout expired" }
            Process.kill(:KILL, *pids) rescue nil
            pids = nil
            retry
          end
        end
        @workers.clear unless cond
        closed
      end

      FakeClass = Struct.new(:name)
      def fake_class(name)
        (@fake_classes ||= {})[name] ||= FakeClass.new(name)
      end

      # Deal with worker events
      def deal(io, type, result, rep, shutting_down = false)
        worker = @workers_hash[io]
        cmd = worker.read
        cmd.sub!(/\A\.+/, '') if cmd # read may return nil

        case cmd
        when ''
          # just only dots, ignore
        when /^_R_: okay$/ # about to run suite
          worker.status = :running
        when /^_R_: ready(!)?$/ # ready to run suite
          bang = $1
          worker.status = :ready

          unless task = @tasks.shift
            worker.quit
            return nil
          end
          if @options[:separate] and not bang
            worker.quit
            worker = launch_worker
          end
          worker.run(task, type)
          @test_count += 1

          jobs_status(worker)
        when /^_R_: start (.+?)$/ # start of method, set current test case of worker
          worker.current = Marshal.load($1.unpack1("m"))
        when /^_R_: done (.+?)$/ # done running suite, collect results
          begin
            r = Marshal.load($1.unpack1("m"))
          rescue
            print "unknown object: #{$1.unpack1("m").dump}"
            return true
          end
          result << r[0..1] unless r[0..1] == [nil,nil]
          rep    << {file: worker.real_file, report: r[2], result: r[3], testcase: r[5]}
          $:.push(*r[4]).uniq!
          jobs_status(worker) if @options[:job_status] == :replace

          return true
        when /^_R_: record (.+?)$/ # recorded hook
          raise "records shouldn't be on" unless need_records?
          begin
            r = Marshal.load($1.unpack1("m"))

            suite = r.first
            key = [worker.name, suite]
            if @records[key]
              @records[key][1] = worker.start_time = Time.now
            else
              @records[key] = [worker.start_time, Time.now]
            end
          rescue => e
            print "unknown record: #{e.message} #{$1.unpack1("m").dump}"
            return true
          end
          record(fake_class(r[0]), *r[1..-1])
        when /^_R_: p (.+?)$/ # finished testcase (test method), update job status
          match = $1
          if $1 =~ /\A([EF]) .+/ # error or failure
            ef_match = $1
            match = match[1..-1]
            msg = match.unpack1("m")
            @report << msg
            del_status_line
            print ef_match
            jobs_status(worker) if @options[:job_status] == :replace
          else
            del_status_line
            print match.unpack1("m")
            jobs_status(worker) if @options[:job_status] == :replace
          end
        when /^_R_: after (.+?)$/ # couldn't load test file
          @warnings << Marshal.load($1.unpack1("m"))
        when /^_R_: bye (.+?)$/ # exception in worker
          after_worker_down worker, Marshal.load($1.unpack1("m"))
        when /^_R_: bye$/, nil
          if shutting_down || worker.quit_called
            after_worker_quit worker
          else
            after_worker_down worker
          end
        else # probably a warning in a sub-process, or a leakcheck report
          del_status_line
          $stdout.puts "#{cmd}"
        end
        return false
      end

      # Initializes the runner to run parallel, and runs all the tests
      # with a number of workers
      def _run_parallel suites, type, result
        raise if worker_process?
        @records = {}

        if @options[:parallel] < 1
          warn "Error: parameter of -j option should be greater than 0."
          return
        end

        # Require needed thing for parallel running
        require 'timeout'
        @tasks = @order.group(@order.sort_by_string(@files)) # Array of filenames.

        @need_quit = false
        @dead_workers = []  # Array of dead workers.
        @warnings = []
        @total_tests = @tasks.size.to_s(10)
        rep = [] # FIXME: more good naming

        @workers      = [] # Array of workers.
        @workers_hash = {} # out-IO => worker
        @ios          = [] # Array of worker IOs
        @job_tokens   = String.new(encoding: Encoding::ASCII_8BIT) if @jobserver
        start = Time.now
        begin
          [@tasks.size, @options[:parallel]].min.times {launch_worker}

          while true
            timeout = [(@workers.filter_map {|w| w.response_at}.min&.-(Time.now) || 0) + @worker_timeout, 1].max
            # XXX: remove me
            #@worker_timeout = 5
            #timeout = 5

            if !(_io = IO.select(@ios, nil, nil, timeout))
              timeout_time = Time.now - @worker_timeout
              # TODO: we don't need to quit a worker if a testcase timed out,
              # we only need to skip to the next test case. If it times out
              # more than once for a suite, then quit.
              quit_workers { |w| w.response_at&.<(timeout_time) }&.each {|w|
                rep << {file: w.real_file, result: nil, testcase: w.current[0], timeout_error: w.current}
              }
            elsif _io.first.any? {|io|
              @need_quit or
                (deal(io, type, result, rep).nil? and
                 !@workers.any? {|x| [:running, :prepare].include? x.status})
            }
              break
            end
            break if @tasks.empty? and @workers.empty?
            if @jobserver and @job_tokens and !@tasks.empty? and
               ((newjobs = [@tasks.size, @options[:parallel]].min) > @workers.size or
                !@workers.any? {|x| x.status == :ready})
              t = @jobserver[0].read_nonblock(newjobs, exception: false)
              if String === t
                @job_tokens << t
                t.size.times {launch_worker}
              end
            end
          end
        rescue Interrupt => ex
          @interrupt = ex
          return result
        ensure
          if file = @options[:timetable_data]
            File.open(file, 'w'){|f|
              @records.each{|(worker, suite), (st, ed)|
                f.puts '[' + [worker.dump, suite.dump, st.to_f * 1_000, ed.to_f * 1_000].join(", ") + '],'
              }
            }
          end

          if @interrupt
            @ios.select!{|x| @workers_hash[x].status == :running }
            while !@ios.empty? && (__io = IO.select(@ios,[],[],10))
              __io[0].reject! {|io| deal(io, type, result, rep, true)}
            end
          end

          quit_workers
          flush_job_tokens

          t = Time.now - start

          # Retry suites that failed in this process
          if !@interrupt && !@need_quit && @options[:retry]
            del_status_line
            parallel = @options[:parallel]
            @options[:parallel] = false
            orig_rep = rep
            failed_suites, rep = rep.partition {|r|
              r[:testcase] && r[:file] &&
                (!r.key?(:report) || r[:report].any? {|e| !e[2].is_a?(Test::Unit::PendedError)})
            }
            failed_suites.map {|r| File.realpath(r[:file])}.uniq.each {|file| require file}
            timed_out_suites, failed_suites = failed_suites.partition {|r| r[:timeout_error]}

            # Report about the run before retrying
            if failed_suites.any? || timed_out_suites.any?
              test_count = assertions = errors = failures = skips = 0
              # NOTE: if a test case timed out, we don't have this info for that suite
              result.each do |r|
                test_count += r[0]
                assertions += r[1]
              end
              orig_rep.each do |r|
                # NOTE: if a test case timed out, we don't have this info for that suite
                if r[:result]
                  errors   += r[:result][0]
                  failures += r[:result][1]
                  skips    += r[:result][2]
                end
              end
              del_status_line
              puts "\nFinished%s %ss in %.6fs, %.4f tests/s, %.4f assertions/s.\n" %
                [(@repeat_count ? "(#{@@current_repeat_count}/#{@repeat_count}) " : ""), type,
                 t, test_count.fdiv(t), assertions.fdiv(t)]
              puts "#{test_count} tests, #{assertions} assertions, #{failures} failures, #{errors} errors, #{skips} skips"
              puts "#{timed_out_suites.size} timeouts" if timed_out_suites.any?
            end

            if failed_suites.any?
              puts "\n""Retrying files:"
              failed_suites.each do |r|
                puts "  #{r[:file]} (#{r[:result][1]} failures, #{r[:result][0]} errors)"
              end
              puts "\n"
              @verbose = options[:verbose]
              failed_suites.map! {|r| ::Object.const_get(r[:testcase])}
              _run_suites(failed_suites, type)
            end
            if timed_out_suites.any?
              puts "\n""Retrying hung up testcases..."
              timed_out_suites = timed_out_suites.map do |r|
                begin
                  ::Object.const_get(r[:testcase])
                rescue NameError
                  # testcase doesn't specify the correct case, so show `r` for information
                  require 'pp'

                  $stderr.puts "Retrying is failed because the file and testcase is not consistent:"
                  PP.pp r, $stderr
                  @errors += 1
                  nil
                end
              end.compact
              verbose = @verbose
              job_status = @options[:job_status]
              @options[:verbose] = @verbose = true
              @options[:job_status] = :normal
              result.concat _run_suites(timed_out_suites, type)
              @options[:verbose] = @verbose = verbose
              @options[:job_status] = job_status
            end
            @options[:parallel] = parallel
          end
          unless @options[:retry]
            del_status_line or puts
          end
          if rep.any?
            rep.each do |r|
              if r[:timeout_error]
                puke(*r[:timeout_error], Timeout::Error.new)
                next
              end
              r[:report]&.each do |f|
                puke(*f) if f
              end
            end
            if @options[:retry]
              rep.each do |x|
                (e, f, s = x[:result]) or next
                @errors   += e
                @failures += f
                @skips    += s
              end
            end
          end
          if @warnings.any?
            warn ""
            @warnings.uniq! {|w| w[1].message}
            @warnings.each do |w|
              warn "#{w[0]}: #{w[1].message} (#{w[1].class})"
            end
            warn ""
          end
        end
      end

      def _run_suites suites, type
        _prepare_run(suites, type)
        result = []
        GC.start
        if @options[:parallel]
          _run_parallel suites, type, result
        else
          suites.each {|suite|
            begin
              result << _run_suite(suite, type)
            rescue Interrupt => e
              @interrupt = e
              break
            end
          }
        end
        del_status_line
        result
      end
    end

    module Skipping # :nodoc: all
      def failed(s)
        super if !s or @options[:hide_skip]
      end

      private

      def setup_options(opts, options)
        super

        opts.separator "skipping options:"

        options[:hide_skip] = true

        opts.on '-q', '--hide-skip', 'Hide skipped tests' do
          options[:hide_skip] = true
        end

        opts.on '--show-skip', 'Show skipped tests' do
          options[:hide_skip] = false
        end
      end

      def _run_suites(suites, type)
        result = super
        @report.reject!{|r| r.start_with? "Skipped:" } if @options[:hide_skip]
        @report.sort_by!{|r| r.start_with?("Skipped:") ? 0 : \
                           (r.start_with?("Failure:") ? 1 : 2) }
        failed(nil)
        result
      end
    end

    module Statistics # :nodoc: all
      def initialize(*, &blk)
        @stats = nil
        super
      end

      def record(suite, method, assertions, time, error)
        return unless need_records?
        if stats
          rec = [suite.name, method, assertions, time, error]
          if max = @options[:longest]
            update_list(stats[:longest], rec, max) {|_,_,_,t,_|t<time}
          end
          if max = @options[:most_asserted]
            update_list(stats[:most_asserted], rec, max) {|_,_,a,_,_|a<assertions}
          end
        end
        # (((@record ||= {})[suite] ||= {})[method]) = [assertions, time, error]
        super
      end

      def run(*args)
        if stats
          show_stats = proc do
            stats.each do |t, list|
              if list
                puts "#{t.to_s.tr('_', ' ')} tests:"
                list.each {|suite, method, assertions, time, error|
                  printf "%5.2fsec(%d): %s#%s\n", time, assertions, suite, method
                }
              end
            end
          end
          trap(:INT) do
            show_stats[]
            abort "Interrupted"
          end
        end
        result = super
        show_stats[] if show_stats
        result
      end

      private

      def setup_options(opts, options)
        super
        opts.separator "statistics options:"
        opts.on '--longest=N', Integer, 'Show longest N tests' do |n|
          options[:longest] = n
        end
        opts.on '--most-asserted=N', Integer, 'Show most asserted N tests' do |n|
          options[:most_asserted] = n
        end
      end

      def need_records?
        @options[:longest] || @options[:most_asserted] || super
      end

      def update_list(list, rec, max)
        if i = list.empty? ? 0 : list.bsearch_index {|*a| yield(*a)}
          list[i, 0] = [rec]
          list[max..-1] = [] if list.size >= max
        end
      end

      def stats
        @stats ||= begin
          if @options[:longest]
            stats = {longest: []}
          end
          if @options[:most_asserted]
            stats ||= {}
            stats[:most_asserted] = []
          end
          stats
        end
      end
    end

    # If in parallel mode, this is just for the main process
    module StatusLine # :nodoc: all
      def initialize(*, &blk)
        @terminal_width = nil
        @status_line_size = 0
        @output = nil
        @colorize = nil
        @report_count = 0
        @tty = $stdout.tty?
        super
      end

      def run(*args)
        result = super
        puts "\nruby -v: #{RUBY_DESCRIPTION}"
        result
      end

      def output
        @output || super
      end

      def new_test(s)
        @test_count += 1
        update_status(s)
      end

      def add_status(line)
        if @options[:job_status] == :replace
          line = line[0...(terminal_width-@status_line_size)]
        end
        print line
        @status_line_size += line.size
      end

      def succeed; del_status_line; end

      def failed(s)
        return if s and @options[:job_status] != :replace
        sep = "\n"
        @report.each do |msg|
          if msg.start_with? "Skipped:"
            if @options[:hide_skip]
              del_status_line
              next
            end
            color = :skip
          else
            color = :fail
          end
          first, msg = msg.split(/$/, 2)
          first = sprintf("%3d) %s", @report_count += 1, first)
          @failed_output.print(sep, @colorize.decorate(first, color), msg, "\n")
          sep = nil
        end
        @report.clear
      end

      private

      def terminal_width
        unless @terminal_width
          begin
            require 'io/console'
            width = $stdout.winsize[1]
          rescue LoadError, NoMethodError, Errno::ENOTTY, Errno::EBADF, Errno::EINVAL
            width = ENV["COLUMNS"].to_i.nonzero? || 80
          end
          width -= 1 if /mswin|mingw/ =~ RUBY_PLATFORM
          @terminal_width = width
        end
        @terminal_width
      end

      def del_status_line(flush = true)
        if @options[:job_status] == :replace
          $stdout.print "\r"+" "*@status_line_size+"\r"
        else
          $stdout.puts if @status_line_size > 0
        end
        $stdout.flush if flush
        @status_line_size = 0
      end

      def jobs_status(worker)
        return if !@options[:job_status] or @verbose
        if @options[:job_status] == :replace
          status_line = @workers.map(&:to_s).join(" ")
        else
          status_line = worker.to_s
        end
        update_status(status_line) or (puts; nil)
      end

      def del_jobs_status
        return unless @options[:job_status] == :replace && @status_line_size.nonzero?
        del_status_line
      end

      def _prepare_run(suites, type)
        raise if worker_process?
        @options[:job_status] ||= :replace if @tty && !@verbose
        case @options[:color]
        when :always
          color = true
        when :auto, nil
          color = true if @tty || @options[:job_status] == :replace
        else
          color = false
        end
        @colorize = Colorize.new(color, colors_file: File.join(__dir__, "../../colors"))
        if color or @options[:job_status] == :replace
          @verbose = !@options[:parallel]
        end
        @output = Output.new(self) unless @options[:testing]
        filter = @options[:test_name_filter] || // # match anything
        type = "#{type}_methods"
        total = suites.inject(0) {|n, suite| n + suite.send(type).grep(filter).size}
        @test_count = 0
        @total_tests = total.to_s(10)
      end

      def update_status(s)
        count = @test_count.to_s(10).rjust(@total_tests.size)
        del_status_line(false)
        add_status(@colorize.pass("[#{count}/#{@total_tests}]"))
        add_status(" #{s}")
        $stdout.print "\r" if @options[:job_status] == :replace and !@verbose
        $stdout.flush
      end

      def setup_options(opts, options)
        super

        opts.separator "status line options:"

        options[:job_status] = nil

        opts.on '--jobs-status [TYPE]', [:normal, :replace, :none],
                "Show status of jobs every file; Disabled when --jobs isn't specified." do |type|
          options[:job_status] = (type || :normal if type != :none)
        end

        opts.on '--color[=WHEN]',
                [:always, :never, :auto],
                "colorize the output.  WHEN defaults to 'always'", "or can be 'never' or 'auto'." do |c|
          options[:color] = c || :always
        end

        opts.on '--tty[=WHEN]',
                [:yes, :no],
                "force to output tty control.  WHEN defaults to 'yes'", "or can be 'no'." do |c|
          @tty = c != :no
        end
      end

      class Output < Struct.new(:runner) # :nodoc: all
        def puts(*a) $stdout.puts(*a) unless a.empty? end
        def respond_to_missing?(*a) $stdout.respond_to?(*a) end
        def method_missing(*a, &b) $stdout.__send__(*a, &b) end

        # Update status line of runner if `s` is in expected format
        def print(s)
          case s
          when /\A(.*\#.*) = \z/
            runner.new_test($1)
          when /\A(.* s) = \z/
            runner.add_status(" = #$1")
          when /\A\.+\z/
            runner.succeed
          when /\A\.*[EFS][EFS.]*\z/
            runner.failed(s)
          else
            # Warnings, etc.
            $stdout.print(s)
          end
        end
      end
    end

    module LoadPathOption # :nodoc: all
      private

      def non_options(files, options)
        begin
          require "rbconfig"
        rescue LoadError
          warn "#{caller(1, 1)[0]}: warning: Parallel running disabled because can't get path to ruby; run specify with --ruby argument"
          options[:parallel] = nil
        else
          options[:ruby] ||= [RbConfig.ruby]
        end

        super
      end

      def setup_options(parser, options)
        super
        parser.separator "load path options:"
        parser.on '-Idirectory', 'Add library load path' do |dirs|
          dirs.split(':').each { |d| $LOAD_PATH.unshift d }
        end
      end
    end

    module GlobOption # :nodoc: all
      @@testfile_prefix = "test"
      @@testfile_suffix = "test"

      def initialize(*, &blk)
        @orig_files = nil
        super
      end

      private

      def setup_options(parser, options)
        super
        parser.separator "globbing options:"
        parser.on '-B', '--base-directory DIR', 'Base directory to glob.' do |dir|
          raise OptionParser::InvalidArgument, "not a directory: #{dir}" unless File.directory?(dir)
          dir = File.expand_path(dir) unless File.absolute_path?(dir)
          (options[:base_directories] ||= []) << dir
        end
        # example: -x /test_hash/
        parser.on '-x', '--exclude REGEXP', 'Exclude test files on pattern.' do |pattern|
          (options[:exclude_file_patterns] ||= []) << pattern
        end
      end

      def complement_test_name f, orig_f
        basename = File.basename(f)

        if /\.rb\z/ !~ basename
          return File.join(File.dirname(f), basename+'.rb')
        elsif /\Atest_/ !~ basename
          return File.join(File.dirname(f), 'test_'+basename)
        end if f.end_with?(basename) # otherwise basename is dirname/

        raise ArgumentError, "file not found: #{orig_f}"
      end

      # Gets list of files from base directory and given files. Changes input `files` array.
      def non_options(files, options)
        @orig_files = files.dup
        if worker_process?
          return super(files, options)
        end
        paths = [options[:base_directories], nil].flatten.uniq
        if exclude_pats = options[:exclude_file_patterns]
          exclude_re = Regexp.union(exclude_pats.map {|r| %r"#{r}"})
        end
        custom_basedirs = options[:base_directories] if options[:base_directories] != [DEFAULT_TEST_DIR]
        if custom_basedirs && files == [DEFAULT_TEST_DIR]
          files.replace custom_basedirs.dup
        elsif custom_basedirs && files != [DEFAULT_TEST_DIR]
          files.concat custom_basedirs
          files.uniq!
        end
        #STDERR.print "files: ", files, "\n"
        files.map! {|f|
          f = f.tr(File::ALT_SEPARATOR, File::SEPARATOR) if File::ALT_SEPARATOR
          orig_f = f
          while true
            #STDERR.print 'f: ', f.inspect, "\n"
            ret = paths.any? do |prefix|
              #STDERR.print 'prefix: ', prefix.inspect, "\n"
              #STDERR.print 'paths: ', paths.inspect, "\n"
              abs_file_no_prefix = false
              if prefix
                if File.absolute_path?(f)
                  path = f
                  abs_file_no_prefix = true
                else
                  path = if f.empty?
                           prefix
                         else
                           path_made = "#{prefix}/#{f}"
                           if File.exist?(File.expand_path(path_made))
                             path_made
                           elsif File.exist?(File.expand_path(f))
                             abs_file_no_prefix = true
                             File.expand_path(f) # file exists outside base directory
                           else
                             next
                           end
                         end
                  #STDERR.print 'made path: ', path, "\n"
                end
              else
                next if f.empty?
                path = f
              end
              #STDERR.print "paths: ", paths.inspect, "\n"
              #STDERR.print "prefix: ", prefix.inspect, "\n"
              #STDERR.print "f: ", f.inspect, "\n"
              #STDERR.print "path: ", path.inspect, "\n"

              path_is_dir = Dir.exist?(path)

              dir = path_is_dir ? path : nil
              if dir
                match = (Dir["#{dir}/**/#{@@testfile_prefix}_*.rb"] + Dir["#{dir}/**/*_#{@@testfile_suffix}.rb"]).uniq
              else
                match = Dir[path]
              end

              if !match.empty?
                if exclude_pats
                  match.reject! {|n|
                    n = if abs_file_no_prefix
                      n
                    else
                      n[(prefix.length+1)..-1] if prefix
                    end
                    exclude_re =~ n
                  }
                end
                break match
              elsif !exclude_pats or (exclude_re !~ f and File.exist?(path))
                break path
              end
            end

            if !ret
              f = complement_test_name(f, orig_f)
            else
              break ret
            end
          end
        }
        files.flatten!
        files.uniq!
        #STDERR.puts "new files: #{files.size}"
        super(files, options)
      end
    end

    module OutputOption # :nodoc: all
      def process_args(args = [])
        return @options if @options
        options = super
        @failed_output = options[:failed_output]
        options
      end

      private

      def setup_options(parser, options)
        super
        parser.separator "output options:"

        options[:failed_output] = $stdout
        parser.on '--stderr-on-failure', 'Use stderr to print failure messages' do
          options[:failed_output] = $stderr
        end
        parser.on '--stdout-on-failure', 'Use stdout to print failure messages', '(default)' do
          options[:failed_output] = $stdout
        end
      end
    end

    module GCOption # :nodoc: all
      private

      def setup_options(parser, options)
        super
        parser.separator "GC options:"
        parser.on '--[no-]gc-stress', 'Set GC.stress as true' do |flag|
          options[:gc_stress] = flag
        end
        parser.on '--[no-]gc-compact', 'GC.compact every time' do |flag|
          options[:gc_compact] = flag
        end
      end

      def non_options(files, options)
        if options.delete(:gc_stress)
          Test::Unit::TestCase.class_eval do
            oldrun = instance_method(:run)
            define_method(:run) do |runner|
              begin
                gc_stress, GC.stress = GC.stress, true
                oldrun.bind_call(self, runner)
              ensure
                GC.stress = gc_stress
              end
            end
          end
        end
        if options.delete(:gc_compact)
          Test::Unit::TestCase.class_eval do
            oldrun = instance_method(:run)
            define_method(:run) do |runner|
              begin
                oldrun.bind_call(self, runner)
              ensure
                GC.compact
              end
            end
          end
        end
        super
      end
    end

    module RequireFiles # :nodoc: all
      class Requirer
        def initialize(files, runner)
          @files = files
          @runner = runner
        end

        def call
          errors = {}
          result = false
          @files.each {|f|
            d = File.dirname(path = File.realpath(f))
            unless $:.include?(d)
              $: << d
            end
            begin
              require path
              result = true
            rescue LoadError
              next if errors[$!.message]
              errors[$!.message] = true
              @runner.puts "#{f}: #{$!}. Skipping it."
            end
          }
          result # at least one file required
        end
      end

      private

      def non_options(files, options)
        return false if !super
        unless options[:parallel]
          options[:requirer] = Requirer.new(files, self)
        end
        true
      end
    end

    module RepeatOption # :nodoc: all
      def initialize(*, &blk)
        @repeat_count = nil
        super
      end

      private

      def setup_options(parser, options)
        super
        options[:repeat_count] = nil
        parser.separator "repeat options:"
        parser.on '--repeat-count=NUM', "Number of times to repeat", Integer do |n|
          @repeat_count = options[:repeat_count] = n
        end
      end
    end

    module ExcludesOption # :nodoc: all
      def initialize(*, &blk)
        @excludes = {}
        super
      end

      class ExcludedMethods < Struct.new(:excludes) # :nodoc: all
        def self.load(dirs, name)
          return unless dirs and name
          instance = nil
          dirs.each do |dir|
            path = File.join(dir, name.gsub(/::/, '/') + ".rb")
            src = File.read(path) if File.exist?(path)
            if src
              instance ||= new({})
              instance.instance_eval(src, path)
            end
          end
          instance
        end

        private

        def exclude(name, reason)
          excludes[name] = reason
        end
      end

      private

      def setup_options(parser, options)
        super
        if excludes = ENV["EXCLUDES"]
          excludes = excludes.split(File::PATH_SEPARATOR)
        end
        options[:excludes] = excludes || []
        parser.separator "excludes options:"
        parser.on '-X', '--excludes-dir DIRECTORY', "Directory name of exclude files" do |d|
          options[:excludes].concat d.split(File::PATH_SEPARATOR)
        end
      end

      def _run_suite(suite, type)
        if excluded = ExcludedMethods.load(@options[:excludes], suite.name)
          (@excludes[[suite.name, type]] ||= {}).merge!(excluded.excludes)
        end
        super
      end
    end

    module TimeoutOption # :nodoc: all
      private

      def setup_options(parser, options)
        super
        parser.separator "timeout options:"
        parser.on '--timeout-scale NUM', '--subprocess-timeout-scale NUM', "Scale timeout", Float do |scale|
          raise OptionParser::InvalidArgument, "timeout scale must be positive" unless scale > 0
          options[:timeout_scale] = scale
        end
      end

      def non_options(files, options)
        if scale = options[:timeout_scale] or
          (scale = ENV["RUBY_TEST_TIMEOUT_SCALE"] || ENV["RUBY_TEST_SUBPROCESS_TIMEOUT_SCALE"] and
           (scale = scale.to_f) > 0)
          EnvUtil.timeout_scale = scale
        end
        super
      end
    end

    class Runner
      attr_reader :report, :failures, :errors, :skips, :start_time # :nodoc:

      ##
      # :attr:
      #
      # if true, installs an "INFO" signal handler (only available to BSD and
      # OS X users) which prints diagnostic information about the test run.
      #
      # This is auto-detected by default but may be overridden by custom
      # runners.

      attr_reader :info_signal

      # Modules are prepended to this class so this is the last in the chain
      def initialize # :nodoc:
        @report = []
        @errors = @failures = @skips = 0
        @test_count = @assertion_count = 0
        @mutex = Thread::Mutex.new
        @info_signal = Signal.list['INFO']
      end

      ##
      # Lazy accessor for options.

      def options
        @options ||= {seed: 42}
      end

      @@installed_at_exit ||= false
      @@out = $stdout
      @@after_tests = []
      @@current_repeat_count = 0

      ##
      # A simple hook allowing you to run a block of code after _all_ of
      # the tests are done. Eg:
      #
      #   Test::Unit::Runner.after_tests { p $debugging_info }

      def self.after_tests &block
        @@after_tests << block
      end

      ##
      # Returns the stream to use for output.

      def self.output
        @@out
      end

      ##
      # Sets Test::Unit::Runner to write output to +stream+.  $stdout is the default
      # output

      def self.output= stream
        @@out = stream
      end

      ##
      # Tells Test::Unit::Runner to delegate to +runner+, an instance of a
      # Test::Unit::Runner subclass, when Test::Unit::Runner#run is called.

      def self.runner= runner
        @@runner = runner
      end

      ##
      # Returns the Test::Unit::Runner subclass instance that will be used
      # to run the tests. A Test::Unit::Runner instance is the default
      # runner.

      def self.runner
        @@runner ||= self.new
      end

      ##
      # Return all plugins' run methods (methods that start with "run_").

      def self.plugins
        @@plugins ||= (["run_tests"] +
                      public_instance_methods(false).
                      grep(/^run_/).map { |s| s.to_s }).uniq
      end

      def self.current_repeat_count # :nodoc:
        @@current_repeat_count
      end

      ##
      # Return the IO for output.

      def output
        self.class.output
      end

      def inspect # :nodoc:
        "#<#{self.class.name}: " <<
        instance_variables.filter_map do |var|
          next if var == :@option_parser # too big
          "#{var}=#{instance_variable_get(var).inspect}"
        end.join(", ") << ">"
      end

      ##
      # Record the result of a single test. Makes it very easy to gather
      # information. Eg:
      #
      #   class StatisticsRecorder < Test::Unit::Runner
      #     def record suite, method, assertions, time, error
      #       # ... record the results somewhere ...
      #     end
      #   end
      #
      #   Test::Unit::Runner.runner = StatisticsRecorder.new
      #
      # NOTE: record might be sent more than once per test.  It will be
      # sent once with the results from the test itself.  If there is a
      # failure or error in teardown, it will be sent again with the
      # error or failure.

      def record suite, method, assertions, time, error
      end

      ##
      # Writes status to +io+

      def status io = self.output
        format = "%d tests, %d assertions, %d failures, %d errors, %d skips"
        io.puts format % [@test_count, @assertion_count, @failures, @errors, @skips]
      end

      ##
      # Begins the full test run. Delegates to +runner+'s #_run method.

      def run(argv = [])
        self.class.runner._run(argv)
      rescue NoMemoryError
        system("cat /proc/meminfo") if File.exist?("/proc/meminfo")
        system("ps x -opid,args,%cpu,%mem,nlwp,rss,vsz,wchan,stat,start,time,etime,blocked,caught,ignored,pending,f") if File.exist?("/bin/ps")
        raise
      end

      ##
      # Top level driver, controls all output and filtering.

      def _run args = []
        args = process_args args # ARGH!! blame test/unit process_args
        @options.merge! args

        puts "Run options: #{@help}"
        if req = @options.delete(:requirer)
          puts "\n# Loading test files"
          req.call
        end

        self.class.plugins.each do |plugin|
          send plugin
          break unless @report.empty?
        end

        return @failures + @errors if @test_count > 0 # or return nil
      rescue Interrupt
        abort 'Interrupted'
      end

      def puke klass, meth, e # :nodoc:
        n = @report.size
        e = case e
            when Test::Unit::PendedError then
              @skips += 1
              return "S" unless @verbose
              "Skipped:\n#{klass}##{meth} [#{location e}]:\n#{e.message}\n"
            when Test::Unit::AssertionFailedError then
              @failures += 1
              "Failure:\n#{klass}##{meth} [#{location e}]:\n#{e.message}\n"
            when Timeout::Error
              @errors += 1
              "Timeout:\n#{klass}##{meth}\n"
            else
              @errors += 1
              bt = Test.filter_backtrace(e.backtrace).join "\n    "
              "Error:\n#{klass}##{meth}:\n#{e.class}: #{e.message.b}\n    #{bt}\n"
            end
        @report << e
        rep = e[0, 1]
        if Test::Unit::PendedError === e and /no message given\z/ =~ e.message
          @report.slice!(n..-1)
          rep = "."
        end
        rep
      end

      def synchronize # :nodoc:
        if @mutex then
          @mutex.synchronize { yield }
        else
          yield
        end
      end

      private

      def puts *a # :nodoc:
        output.puts(*a)
      end

      def print *a # :nodoc:
        output.print(*a)
      end

      ##
      # Run all suites for a given +type+

      def _run_anything type
        suites = Test::Unit::TestCase.send "#{type}_suites"
        return if suites.empty?

        suites = @order.sort_by_name(suites)

        puts
        puts "# Running #{type}s:"
        puts

        @test_count, @assertion_count = 0, 0
        test_count = assertion_count = 0
        sync = output.respond_to? :"sync=" # stupid emacs
        old_sync, output.sync = output.sync, true if sync

        @@current_repeat_count = 0
        begin
          start = Time.now

          results = _run_suites suites, type

          @test_count      = results.inject(0) { |sum, (tc, _)| sum + tc }
          @assertion_count = results.inject(0) { |sum, (_, ac)| sum + ac }
          test_count      += @test_count
          assertion_count += @assertion_count
          t = Time.now - start
          @@current_repeat_count += 1
          unless @repeat_count
            puts
            puts
          end
          puts "Finished%s %ss in %.6fs, %.4f tests/s, %.4f assertions/s.\n" %
              [(@repeat_count ? "(#{@@current_repeat_count}/#{@repeat_count}) " : ""), type,
                t, @test_count.fdiv(t), @assertion_count.fdiv(t)]
        end while @repeat_count && @@current_repeat_count < @repeat_count &&
                  @report.empty? && @failures.zero? && @errors.zero?

        output.sync = old_sync if sync

        @report.each_with_index do |msg, i|
          puts "\n%3d) %s" % [i + 1, msg]
        end

        puts
        @test_count      = test_count
        @assertion_count = assertion_count

        status
      end

      ##
      # Run a single +suite+ for a given +type+.

      def _run_suite suite, type
        header = "#{type}_suite_header"
        puts send(header, suite) if respond_to? header

        filter = @options[:test_name_filter]

        all_test_methods = suite.send "#{type}_methods"
        if filter
          all_test_methods.select! {|method|
            filter === "#{suite}##{method}"
          }
        end
        excludes = @excludes[[suite.name, type]]
        if excludes
          all_test_methods.reject! {|method|
            excludes.any? { |pat, _| pat === method }
          }
        end
        all_test_methods = @order.sort_by_name(all_test_methods)

        leakchecker = LeakChecker.new(output: self.class.output, use_buffered_output: worker_process?)
        if ENV["LEAK_CHECKER_TRACE_OBJECT_ALLOCATION"]
          require "objspace"
          trace = true
        end

        assertions = all_test_methods.map { |method|
          inst = suite.new(method)
          _start_method(inst)

          print "#{suite}##{method} = " if @verbose

          start_time = Time.now if @verbose
          result =
            if trace
              ObjectSpace.trace_object_allocations {inst.run self}
            else
              inst.run self
            end

          print "%.2f s = " % (Time.now - start_time) if @verbose
          print result
          puts if @verbose
          $stdout.flush

          unless defined?(RubyVM::MJIT) && RubyVM::MJIT.enabled? # compiler process is wrongly considered as leak
            leakchecker.check("#{inst.class}\##{inst.__name__}")
          end

          _end_method(inst)

          inst._assertions
        }
        return assertions.size, assertions.inject(0) { |sum, n| sum + n }
      end

      def _start_method(inst) # :nodoc:
      end

      def _end_method(inst) # :nodoc:
      end

      ##
      # For performance reasons, records are not always sent across processes
      # in parallel mode. If you need records, you must override this, even in
      # non-parallel mode.

      def need_records?
        not @options[:parallel]
      end

      def location e # :nodoc:
        last_before_assertion = ""

        return '<empty>' unless e.backtrace # SystemStackError can return nil.

        e.backtrace.reverse_each do |s|
          break if s =~ /in .(assert|refute|flunk|pass|fail|raise|must|wont)/
          last_before_assertion = s
        end
        last_before_assertion.sub(/:in .*$/, '')
      end


      ##
      # Runs test suites

      def run_tests
        _run_anything :test
      end

      prepend Test::Unit::Options
      prepend Test::Unit::StatusLine
      prepend Test::Unit::Parallel
      prepend Test::Unit::Statistics
      prepend Test::Unit::Skipping
      prepend Test::Unit::GlobOption
      prepend Test::Unit::OutputOption
      prepend Test::Unit::RepeatOption
      prepend Test::Unit::LoadPathOption
      prepend Test::Unit::GCOption
      prepend Test::Unit::ExcludesOption
      prepend Test::Unit::TimeoutOption
      prepend Test::Unit::RunCount

      @@stop_auto_run = false
      def self.autorun
        at_exit {
          Test::Unit::RunCount.run_once {
            exit(Test::Unit::Runner.new.run(ARGV) || true)
          } unless @@stop_auto_run
        } unless @@installed_at_exit
        @@installed_at_exit = true
      end

      alias orig_run_suite _run_suite
    end

    class AutoRunner # :nodoc: all
      class Runner < Test::Unit::Runner
        include Test::Unit::RequireFiles
      end

      attr_reader :options

      def initialize(force_standalone = false, default_dir = nil, argv = ARGV)
        @force_standalone = force_standalone
        @to_run = nil
        @runner = Runner.new do |runner, files, options|
          bases = options[:base_directories] ||= [default_dir]
          bases = bases.map do |base|
            File.absolute_path?(base) ? base : File.expand_path(base)
          end
          files << default_dir if files.empty? and default_dir
          @to_run = files
          yield self if block_given?
          bases.each do |base|
            $LOAD_PATH.unshift base if base
          end
          $LOAD_PATH.unshift DEFAULT_TEST_DIR unless $:.include?(DEFAULT_TEST_DIR)
          runner.default_dir = default_dir
          files
        end
        Runner.runner = @runner
        @options = @runner.option_parser
        if @force_standalone
          @options.banner.sub!(/\[options\]/, '\& tests...')
        end
        @argv = argv
      end

      def self.run(*args)
        new(*args).run
      end

      def run
        if @force_standalone and not process_args(@argv)
          abort @options.banner
        end
        @runner.run(@argv) || true
      end

      private

      def process_args(*args)
        return if @to_run
        @runner.process_args(*args)
        @to_run.any?
      end
    end

    class ProxyError < StandardError # :nodoc: all
      attr_reader :message, :backtrace

      def initialize(ex)
        @message = ex.message
        @backtrace = ex.backtrace
      end
    end
  end
end

Test::Unit::Runner.autorun

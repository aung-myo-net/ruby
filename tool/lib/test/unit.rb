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
        include MJITFirst

        def sort_by_name(list)
          list.sort_by(&:name)
        end

        def sort_by_string(list)
          list.sort
        end

      end

      # shuffle test suites based on CRC32 of their names
      Shuffle = Struct.new(:seed, :salt) do # :nodoc: all
        include MJITFirst

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

        # XXX: remove to use MJITFirst
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

      def initialize(*, &block)
        @init_hook = block
        @options = nil
        @run_options = nil
        @help = nil
        @order = nil
        @verbose = false
        @option_parser = OptionParser.new
        @option_warnings = []
        super(&nil)
      end

      def process_args(args = [])
        return @options if @options
        orig_args = args.dup
        options = {}
        setup_options(@option_parser, options)
        @option_parser.parse!(args)
        orig_args -= args
        @run_options = orig_args
        args = @init_hook.call(self, args, options) if @init_hook
        non_options(args, options)

        order = options[:test_order]
        if seed = options[:seed]
          order ||= :random
        elsif (order ||= :random) == :random
          seed = options[:seed] = rand(0x10000)
          @run_options.unshift "--seed=#{seed}"
        end
        Test::Unit::TestCase.test_order = order if order
        order = Test::Unit::TestCase.test_order
        @order = Test::Unit::Order::Types[order].new(seed)

        @help = "\n" + orig_args.map { |s|
          "  " + (s =~ /[\s|&<>$()]/ ? s.inspect : s)
        }.join("\n")

        if @orig_files.any? && @orig_files != [options[:base_directory]]
          @help << "\n  #{@orig_files.inspect}\n"
        end

        @options = options # first time @options is set
      end

      private

      def setup_options(opts, options)
        opts.separator 'test-unit options:'

        options[:report_after] = false
        options[:verbose] = false

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

        # NOTE: when filtering on !/REGEXP/ and using a shell like bash, you
        # must escape ! with a backslash.
        opts.on '-n', '--name PATTERN', "Filter TestClass#test_example on pattern: /REGEXP/, !/REGEXP/ or STRING" do |a|
          (options[:test_name_filter] ||= []) << a
        end

        orders = Test::Unit::Order::Types.keys
        opts.on "--test-order=#{orders.join('|')}", "default=random" do |a|
          options[:test_order] = a
        end

        opts.on('--without-leakchecker', "Turn off leakchecker") do
          options[:without_leakchecker] = true
        end

        opts.on('--report-failures-after', "Report failures only after all tests have ran instead of immediately") do
          options[:report_after] = true
        end
      end

      class TestNameFilter # :nodoc: all
        attr_reader :pat

        def initialize(pat)
          @pat = pat
          @is_string_pat = true
          if String === pat
          elsif Regexp === pat
            @is_string_pat = false
          else
            raise ArgumentError, "Expect String or Regexp"
          end
        end

        def regexp!
          raise "pat should be Regexp" if @is_string_pat
          @pat
        end

        def regexp_string_to_regexp
          raise unless regexp_string?
          options = 0
          options = Regexp::IGNORECASE if @opt_i
          Regexp.new(regexp_string_match, options)
        end

        # Is this string like "/something/" or "!/something/"
        def regexp_string?
          return false unless @is_string_pat
          @regexp_string ||= (pos_regexp_string? || neg_regexp_string?)
        end

        # Check that this is not a regexp string like "/something/", just a regular string
        def check_plain_string!
          raise unless plain_string?
        end

        # is this string like "/something/"
        def pos_regexp_string?
          return false unless @is_string_pat
          @pos_pat ||= begin
            res = ((/\A\/(.*)\/([i])?\z/ =~ @pat) ? true : false)
            if res
              @pat_match = $1
              @opt_i = $2
            end
            res
          end
        end

        # is this string like "!/something/"
        def neg_regexp_string?
          return false unless @is_string_pat
          @neg_pat ||= begin
            res = ((/\A!\/(.*)\/([i])?\z/ =~ @pat) ? true : false)
            if res
              @pat_match = $1
              @opt_i = $2
            end
            res
          end
        end

        # extract "something" from "/something/" or "!/something/
        def regexp_string_match
          raise unless regexp_string?
          @pat_match
        end

        def fully_qualified_test_method_string?
          return false unless plain_string?
          @pat =~ /\A[A-Z]\w*(?:::[A-Z]\w*)*#/
        end

        private

        def plain_string?
          @is_string_pat && !regexp_string?
        end
      end

      # Change options[:test_name_filter] from Array of strings/regexps to single regexp
      def non_options(files, options)
        filter = options[:test_name_filter]
        if filter
          filter.map! { |pat| TestNameFilter.new(pat) }
          negative, positive = filter.partition {|filt| filt.neg_regexp_string? }
          if positive.empty?
            filter = nil
          else
            pos_rs = positive.map {|filt|
              if filt.pos_regexp_string?
                r = filt.regexp_string_to_regexp
              end
              # a plain string is given, it must match exactly with test name
              if !r
                filt.check_plain_string!
                if filt.fully_qualified_test_method_string?
                  pat_s = Regexp.quote(filt.pat)
                  r = /\A#{pat_s}\z/
                else
                  r = /##{Regexp.quote(filt.pat)}\z/
                end
              end
              r
            }
            filter = TestNameFilter.new(Regexp.union(*pos_rs))
          end
          if negative.any?
            neg_rs = negative.map { |filt| filt.regexp_string_to_regexp }
            neg_r = Regexp.union(*neg_rs)
            if filter
              filter_r = /\A(?=.*#{filter.regexp!})(?!.*#{neg_r})/
            else
              filter_r = /\A(?!.*#{neg_r})/
            end
            filter = TestNameFilter.new(filter_r)
          end
          options[:test_name_filter] = filter.regexp!
          if (debug = ENV.delete("DEBUG_TEST_NAME_FILTER")) && debug != '0'
            $stderr.puts options[:test_name_filter]
          end
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
        @last_test_assertions = 0 # Used only in worker process
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
        # TODO: document how to use this and what it's for
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

        options[:retry_timeouts] = true
        options[:retry_failures] = true

        opts.on '-j N', '--jobs N', /\A(t)?(\d+)\z/, "Allow run tests with N jobs (workers) at once" do |_, t, a|
          options[:testing_parallel] = true & t # For testing
          options[:parallel] = a.to_i
        end

        opts.on '--worker-timeout=N', Integer, "Timeout workers not responding in N seconds" do |a|
          options[:worker_timeout] = a
        end

        opts.on '--separate', "Restart worker process after one testcase (file) has finished" do
          options[:parallel] ||= 1
          options[:separate_worker_per_suite] = true
        end

        # The default is retry suites (files) that timed out or had failures.
        # The retry is done in the current process, not by worker processes.
        # Failures here means assertion failures OR uncaught exceptions (errors).
        opts.on '--retry=failures|timeouts|all|none', "Retry the files that timed out or failed" do |_retry|
          case _retry
          when 'all'
            options[:retry_timeouts] = true
            options[:retry_failures] = true
          when 'timeouts'
            options[:retry_timeouts] = true
            options[:retry_failures] = false
          when 'failures'
            options[:retry_timeouts] = false
            options[:retry_failures] = true
          when 'none'
            options[:retry_timeouts] = false
            options[:retry_failures] = false
          end
        end

        opts.on '--no-retry', "Don't retry files with failures or timeouts. Same as --retry=none" do
          options[:retry_timeouts] = false
          options[:retry_failures] = false
        end

        opts.on '--ruby VAL', "Path to ruby which is used for workers" do |a|
          options[:ruby] = a.split(/ /).reject(&:empty?)
        end

        # TODO: document what this is for
        opts.on '--timetable-data=FILE', "Path to timetable data" do |a|
          options[:timetable_data] = a
        end

        opts.on('--silence-worker-output', "Silence worker $stderr, $stdout and leakchecker") do
          options[:silence_worker_output] = true
        end
      end

      def recording?
        @options[:timetable_data] || super
      end

      # Set $VERBOSE or $DEBUG manually when debugging
      def debug
        if $VERBOSE || $DEBUG
          del_status_line
          $stderr.puts yield
        end
      end

      class Worker # :nodoc: all
        def self.launch(ruby,args=[])
          old_report_on_exception = Thread.current.report_on_exception
          # IO.popen spawns a new thread that will inherit this value. Because
          # we don't want it to output any errors (which usually happens
          # during INT signal), we set this value.
          Thread.current.report_on_exception = false
          scale = EnvUtil.timeout_scale
          io = IO.popen([*ruby, "-W1",
                        "#{__dir__}/unit/parallel.rb",
                        *("--timeout-scale=#{scale}" if scale),
                        *args, { err: [:child, :out] }], "rb+")
          new(io, io.pid, :waiting)
        ensure
          Thread.current.report_on_exception = old_report_on_exception
        end

        attr_reader :num, :io, :pid, :real_file, :quit_called, :response_at, :error
        attr_accessor :start_time, :current, :status
        attr_accessor :suite_test_total, :suite_test_count, :suite_assertion_count, :suite_errors, :suite_failures,
                      :suite_skips

        @@worker_number = 0

        def initialize(io, pid, status)
          @num = (@@worker_number += 1)
          @io = io # stdout/stderr from the worker process
          @pid = pid
          @status = status # one of :prepare, :ready, :running, :awaiting_quit_response, :exited, :killed
          @file = nil # current file name being run (base name)
          @real_file = nil # current file name being run (full path)
          @loadpath = []
          @hooks = {}
          @quit_called = false
          @response_at = nil # last response from worker
          @start_time = nil
          @current = nil # array of ["TestCaseName"", :test_method_name]
          # Normally suite results are sent by a worker process when it's
          # finished the suite, but if the worker times out we want access to
          # this information, so we keep track of it here:
          @suite_test_count = 0 # number of tests run so far in current file
          @suite_test_total = 0 # number of total tests for current file
          @suite_assertion_count = 0 # number of assertions made so far in current suite
          # These numbers are a best-effort attempt, because the output of the worker
          # is parsed to get them. The real data is sent when the suite is finished.
          @suite_errors = @suite_failures = @suite_skips = 0
          @error = nil # Exception in communication with worker process
        end

        def name
          "Worker #{@num}"
        end

        def current_test_name
          if @current
            "#{@current[0]}##{@current[1]}"
          else
            nil
          end
        end

        def puts(*args)
          @io.puts(*args)
        end

        # Communicates with worker process to run a test file
        def run(task,type)
          @suite_test_total = @suite_test_count = @suite_assertion_count = 0
          @suite_errors = @suite_failures = @suite_skips = 0
          @file = File.basename(task, ".rb")
          dir = File.dirname(task)
          @real_file = task
          begin
            puts "loadpath #{[Marshal.dump($:-@loadpath+[dir])].pack("m0")}"
            @loadpath = $:.dup
            puts "run #{task} #{type}"
            @status = :prepare
            @start_time = Time.now
            @response_at = @start_time
          rescue Errno::EPIPE => e
            @error = e
            died
          rescue IOError => e
            @error = e
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
          res = (@status == :awaiting_quit_response) ? @io.read : @io.gets
          @response_at = Time.now
          res && res.chomp
        end

        def close
          @io.close unless @io.closed?
          self
        rescue IOError
        end

        # Send "quit" message to worker process. This does not make the process
        # exit immediately, as it first has to finish its test suite.
        # TODO: send a signal to the worker instead of sending msg to `io` so
        # it can respond immediately.
        def quit(warn_if_closed: true)
          if @io.closed?
            @quit_called = true
            @status = :awaiting_quit_response if @status == :running
            return
          end
          return if @quit_called
          @quit_called = true
          old_status = @status
          @status = :awaiting_quit_response
          @io.puts "quit"
        rescue Errno::EPIPE => e
          @error = e
          if warn_if_closed
            warn "Tried to send 'quit' to #{@pid}:#{old_status.to_s.ljust(7)}:#{@file}: #{e.message}"
          end
        end

        def kill
          Process.kill(:KILL, @pid)
          @status = :killed
        rescue Errno::ESRCH
        end

        # Worker process can no longer be communicated with (may have exited)
        def died(*additional)
          @status = :exited
          @io.close
          status = $?
          if status and status.signaled?
            additional[0] ||= SignalException.new(status.termsig)
          end

          call_hook(:dead, *additional)
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
        worker.status = :exited
        return if @interrupt
        del_status_line
        flush_job_tokens
        warn e if e
        warn ""
        real_file = worker.real_file and warn "Error while running file: #{real_file}"
        warn ""
        warn "A test worker crashed at #{worker.current_test_name}. It might be an interpreter bug or"
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
        quit_workers
        STDERR.flush
        exit c
      end

      def after_worker_exit(worker)
        worker.status = :exited
        return if @interrupt
        worker.close
        if @jobserver and (token = @job_tokens.slice!(0))
          @jobserver[1] << token
        end
        delete_worker(worker)
        @dead_workers << worker
        jobs_status(worker: nil)
      end

      def launch_worker
        begin
          worker = Worker.launch(@options[:ruby], @run_options)
        rescue => e
          abort "ERROR: Failed to launch job process - #{e.class}: #{e.message}"
        end
        worker.hook(:dead) do |w,info|
          after_worker_exit w
          after_worker_down w, *info if !info.empty? && !worker.quit_called
        end
        @workers << worker
        @ios << worker.io
        @workers_hash[worker.io] = worker
        worker
      end

      def delete_worker(worker)
        @workers.delete worker
        @ios.delete worker.io
        @workers_hash.delete worker.io
      end

      # Stop the worker processes. If `cond` is given, only
      # stop the workers that meet this condition. We wait a little
      # while until the workers have finished their current suite before force
      # killing them. When this returns, these worker processes will no longer
      # be running.
      def quit_workers(reason: nil, timeout: nil, &cond)
        return @workers if @workers.empty?
        #$VERBOSE = 1 # debugging
        quit_workers = []
        killed_workers = []
        @workers.each do |worker|
          if cond
            next unless cond.call(worker)
            if reason == :timeout
              del_status_line
              $stdout.puts "Timeout in #{worker.current_test_name} after #{timeout} seconds"
            end
          end
          # An interrupt signal might have been sent to child, in which case the child
          # will already be exited, so we don't want warnings
          begin
            Timeout.timeout(1) do
              worker.quit(warn_if_closed: false)
            end
          rescue Timeout::Error
          end
          begin
            Timeout.timeout(0.2) do
              worker.close
            end
          rescue Timeout::Error
            debug { "Killing worker #{worker.pid} after close timeout expired" }
            worker.kill
            killed_workers << worker
            jobs_status(except: killed_workers)
            retry
          end
          quit_workers << worker
        end

        killed_workers.each do |w|
          delete_worker(w)
        end

        if quit_workers.empty?
          return quit_workers
        end
        killing = quit_workers - killed_workers
        return quit_workers if killing.empty? # already killed above

        pids = killing.map(&:pid)
        pids.each { |pid|
          begin
            t = 0.2
            # Wait for suites to finish after call to `quit`. If they've been sent an interrupt signal they will
            # finish immediately.
            Timeout.timeout(t) do
              begin
                Process.waitpid(pid)
              rescue Errno::ECHILD
              end
            end
          rescue Timeout::Error
            debug { "Killing (sig 9) worker process #{pid} after waitpid timeout expired (#{t}s)" }
            Process.kill(:KILL, pid) rescue nil
          end
        }
        killing.each do |w|
          w.status = :killed
          delete_worker(w)
        end
        quit_workers
      end

      FakeClass = Struct.new(:name)
      def fake_class(name)
        (@fake_classes ||= {})[name] ||= FakeClass.new(name)
      end

      # Deal with worker events. Return `nil` when no more events for the io, `true` if suite results have
      # been collected or they cannot be collected (due to error), and `false` otherwise.
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
          bang = $1 # the ! means it hasn't run any suites before
          worker.status = :ready

          unless task = @tasks.shift
            worker.quit # don't remove from @workers, let it go through "bye" procedure
            return nil
          end
          if @options[:separate_worker_per_suite] and not bang
            worker.quit
            worker = launch_worker
          end
          worker.run(task, type)
          @test_count += 1

          jobs_status(worker: worker)
        when /^_R_: start (.+?)$/ # start of method, set current test case of worker
          ary = Marshal.load($1.unpack1("m"))
          worker.current = ary.first(2)
          last_test_assertions = ary[2]
          worker.suite_assertion_count += last_test_assertions
          worker.suite_test_count += 1
        when /^_R_: running file ([0-9]+)$/
          worker.suite_test_total = $1.to_i
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
          jobs_status(worker: worker) if @options[:job_status] == :replace
          return true
        when /^_R_: record (.+?)$/ # recorded hook
          raise "records shouldn't be on" unless recording?
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
        when /^_R_: p (.+?)$/ # test runner output, like '.' or 'E'
          match = $1
          if ((!@verbose) && match =~ /\A([EFS]) (.+)\z/) ||
              (@verbose && match =~ /\A(.+? s = ([EFS])) \|\| (.+?)\z/) # error or failure in non-verbose mode
            if @verbose
              msg = $1 + "\n"
              err = $3.unpack1("m")
            else
              msg = $1
              err = $2.unpack1("m")
            end
            unless @interrupt
              @report << err
              del_status_line
              if @verbose
                efs_change = print_verbose(msg, test_count: worker.suite_test_count, total_tests: worker.suite_test_total) # print the error or failure
              else
                efs_change = print(msg) # print the error or failure
              end
              if efs_change != [0,0,0]
                worker.suite_errors += efs_change[0]
                worker.suite_failures += efs_change[1]
                worker.suite_skips += efs_change[2]
              end
              jobs_status(worker: worker) if @options[:job_status] == :replace
            end
          else
            unless @interrupt
              del_status_line
              status_msg = match.unpack1("m")
              if @verbose
                efs_change = print_verbose(status_msg, test_count: worker.suite_test_count, total_tests: worker.suite_test_total) # long msg
              else
                efs_change = print status_msg # '.' or 'S' or long result if verbose mode
              end
              if efs_change != [0,0,0]
                worker.suite_errors += efs_change[0]
                worker.suite_failures += efs_change[1]
                worker.suite_skips += efs_change[2]
              end
              jobs_status(worker: worker) if @options[:job_status] == :replace
            end
          end
        when /^_R_: after (.+?)$/ # couldn't load test file
          unless @interrupt
            w = Marshal.load($1.unpack1("m"))
            # TODO: maybe we should treat this as an error
            unless @warnings.include?(w[1].message)
              @failed_output.puts "#{w[1].message} (#{w[1].error_class})"
              @failed_output.puts ""
              @warnings << w[1].message
            end
          end
        when /^_R_: bye (.+?)$/ # exception in worker
          unless @interrupt
            error_msg = Marshal.load($1.unpack1("m"))
            after_worker_down worker, error_msg
          end
          return true
        when /^_R_: bye$/, nil
          if shutting_down || worker.quit_called
            after_worker_exit worker
          else
            after_worker_down worker
          end
          return true
        else
          # probably a warning in a sub-process. $stderr of worker processes gets here
          # Also if worker outputs directly to $stdout instead of going through the runner's output
          # it ends up here.
          if !@options[:silence_worker_output] && !@interrupt
            del_status_line
            $stdout.puts "#{cmd}"
            $stdout.flush
          end
        end
        false
      end

      # Initializes the runner to run parallel, and runs all the tests
      # in a number of worker processes
      def _run_parallel suites, type, result
        raise if worker_process?
        @records = {}

        if @options[:parallel] < 1
          warn "Error: parameter of -j option should be greater than 0."
          return
        end

        require 'timeout'
        @tasks = @order.group(@order.sort_by_string(@files)) # Array of filenames.

        @dead_workers = [] # Worker objects that don't have a running process
        @warnings = []
        @total_tests = @tasks.size.to_s(10)
        rep = [] # report results

        @workers      = [] # array of Worker objects
        @workers_hash = {} # out-IO => Worker
        @ios          = [] # Array of worker IOs
        @job_tokens   = String.new(encoding: Encoding::ASCII_8BIT) if @jobserver
        start = Time.now
        begin
          while true
            worker_size = [@tasks.size, @options[:parallel]].min
            if @workers.size < worker_size
              (worker_size-@workers.size).times { launch_worker }
            end
            # Get the minimum timeout needed based on the oldest Worker#response_at
            timeout = [(@workers.filter_map {|w| w.response_at || Time.now}.min&.-(Time.now) || 0) + @worker_timeout, 1].max
            # XXX: just for debugging
            #@worker_timeout = 5
            #timeout = 5

            if !(_io = IO.select(@ios, nil, nil, timeout))
              timeout_time = Time.now - @worker_timeout
              # TODO: we shouldn't quit a worker if a testcase timed out,
              # we only need to skip to the next test case. If it times out
              # more than once for a suite, then quit.
              quit_workers(reason: :timeout, timeout: @worker_timeout) { |w| w.response_at && w.response_at < timeout_time }.each  do |w|
                result << [w.suite_test_count, w.suite_assertion_count, :timeout]
                rep << {
                  file: w.real_file, result: [w.suite_errors, w.suite_failures, w.suite_skips],
                  testcase: w.current[0], timeout_error: w.current
                }
              end
            elsif _io.first.any? {|io|
              # no tasks left, break out
              (deal(io, type, result, rep).nil? and
               @workers.none? {|x| [:running, :prepare].include? x.status})
            }
              break
            end
            break if @tasks.empty? and @workers.empty?
            if @jobserver and @job_tokens and @tasks.any? and
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
            # Get "done" message from interrupted workers with their partial results
            @ios.select! do |x|
              [:running, :awaiting_quit_response].include?(@workers_hash[x].status)
            end
            begin
              Timeout.timeout(3) do
                while @ios.any? && (__io = IO.select(@ios,[],[],3))
                  _io = __io[0][0]
                  @ios.reject! {|io|
                    next unless _io.fileno == io.fileno
                    res = deal(io, type, result, rep, true)
                    res.nil? || res
                  }
                end
              end
            rescue Timeout::Error
            end
          end

          quit_workers
          flush_job_tokens

          time_taken = Time.now - start

          if @interrupt
            parallel_report(result, rep, time_taken, type)
            abort "Interrupted"
          end

          if @options[:report_after] && @report.size > 0
            $stdout.puts
            output_error_messages
          end

          orig_rep = rep
          # Failed errors are already output, so we can partition these and re-assign `rep`
          failed_suites, rep = rep.partition {|r|
            r[:testcase] && r[:file] &&
              (!r.key?(:report) || r[:report].any? {|e| !e[2].is_a?(Test::Unit::PendedError)})
          }
          if @options[:repeat_count].to_i > 1
            failed_suites.each do |r|
              r[:report].each do |e|
                @report << "#{e[0]}##{e[1]}: #{e[2].message}"
              end
            end
          end

          if @options[:retry_failures] || @options[:retry_timeouts]
            failed_suites.map {|r| File.realpath(r[:file])}.uniq.each {|file| require file}
            timed_out_suites, failed_suites = failed_suites.partition {|r| r[:timeout_error]}
            @report_count = 0
            del_status_line

            # Report about the run before retrying
            if failed_suites.any? || timed_out_suites.any?
              parallel_report(result, orig_rep, time_taken, type)
              puts "#{timed_out_suites.size} timeouts" if timed_out_suites.any?
            end

            old_parallel = @options[:parallel]
            @options[:parallel] = false
          end

          # Retry suites that failed in this process
          if @options[:retry_failures]
            if failed_suites.any?
              puts "\n""Retrying files:"
              failed_suites.each do |r|
                puts "  #{r[:file]} (#{r[:result][1]} failures, #{r[:result][0]} errors)"
              end
              puts "\n"
              @verbose = @options[:verbose]
              failed_suites.map! {|r| ::Object.const_get(r[:testcase])}
              _run_suites(failed_suites, type)
            end
          end
          # Retry suites that timed out in this process
          if @options[:retry_timeouts]
            if timed_out_suites.any?
              puts "\n""Retrying hung up testcases..."
              timed_out_suites = timed_out_suites.map do |r|
                begin
                  ::Object.const_get(r[:testcase])
                rescue NameError
                  # testcase doesn't specify the correct case, so show `r` for information
                  require 'pp'

                  $stderr.puts "Retrying failed because the file and testcase is not consistent:"
                  PP.pp r, $stderr
                  @errors += 1
                  nil
                end
              end.compact
              old_verbose = @verbose
              old_job_status = @options[:job_status]
              @options[:verbose] = @verbose = true
              @options[:job_status] = :normal
              result.reject! { |ary| ary[2] == :timeout }
              result.concat _run_suites(timed_out_suites, type)
              @options[:verbose] = @verbose = old_verbose
              @options[:job_status] = old_job_status
            end
          end

          if @options[:retry_timeouts] || @options[:retry_failures]
            # This is necessary if there's a repeat_count > 1
            @options[:parallel] = old_parallel
          end

          if @repeat_count.to_i > 1 || !@options[:retry_failures]
            del_status_line
            orig_rep.each do |x|
              (e, f, s = x[:result]) or next
              @errors   += e
              @failures += f
              @skips    += s
            end
          end
        end
      end

      def _run_suites suites, type
        _prepare_run_suites(suites, type)
        result = []
        GC.start
        if @options[:parallel]
          _run_parallel suites, type, result
        else
          suites.each {|suite|
            begin
              result << _run_suite(suite, type)
              gc_suite(suite, type) if can_gc_suite?(suite, type)
            rescue Interrupt => e
              result << [@suite_test_count, @suite_assertion_count]
              @interrupt = e
              break
            end
          }
        end
        del_status_line
        result
      end

      # Report on all suites ran
      def parallel_report(result, report, time_taken, type)
        test_count = assertions = errors = failures = skips = 0
        result.each do |r|
          test_count += r[0]
          assertions += r[1]
        end
        report.each do |r|
          errors   += r[:result][0]
          failures += r[:result][1]
          skips    += r[:result][2]
        end
        del_status_line
        puts "\nFinished%s %ss in %.6fs, %.4f tests/s, %.4f assertions/s.\n" %
          [(@repeat_count ? " (#{self.class.current_repeat_count+1}/#{@repeat_count})" : ""), type,
           time_taken, test_count.fdiv(time_taken), assertions.fdiv(time_taken)]
        puts "#{test_count} tests, #{assertions} assertions, #{failures} failures, #{errors} errors, #{skips} skips"
      end
    end

    module Skipping # :nodoc: all
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
        # report failures
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
        return unless recording?
        if stats
          rec = [suite.name, method, assertions, time, error]
          if max = @options[:longest]
            update_list(stats[:longest], rec, max) {|_,_,_,t,_|t<time}
          end
          if max = @options[:most_asserted]
            update_list(stats[:most_asserted], rec, max) {|_,_,a,_,_|a<assertions}
          end
        end
         #(((@record ||= {})[suite] ||= {})[method]) = [assertions, time, error]
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

      def recording?
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
          stats = nil
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
        @force_tty = nil
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

      def new_test(s, test_count: nil, total_tests: nil)
        raise if worker_process?
        unless @options[:parallel]
          @test_count += 1
        end
        if @options[:job_status] == :none
          $stdout.print s
        else
          update_status(s, test_count: test_count, total_tests: total_tests)
        end
      end

      def add_status(line)
        raise if worker_process?
        if @options[:job_status] == :replace
          line = line[0...(terminal_width-@status_line_size)]
        end
        $stdout.print line
        @status_line_size += line.size unless @options[:job_status] == :none
      end

      def succeed
        raise if worker_process?
        if @verbose
          $stdout.print " = ."
        end
        del_status_line
      end

      def failed(s, status: 'F')
        raise if worker_process?
        return if @options[:report_after]
        if s && @verbose
          $stdout.print " = #{status}"
        end
        output_error_messages
        @report.clear
      end

      private

      def output_error_messages
        sep = "\n"
        @report.each do |msg|
          if msg.start_with? "Skipped:"
            if @options[:hide_skip]
              del_status_line
              next
            end
            color = "skip"
          else
            color = "fail"
          end
          first, msg = fmt_error_message(msg)
          @failed_output.print(sep, @colorize.decorate(first, color), msg, "\n")
          sep = nil
        end
      end

      def fmt_error_message(msg)
        first, msg = msg.split(/$/, 2)
        first = sprintf("%3d) %s", @report_count += 1, first)
        [first, msg]
      end

      def use_tty?
        if @force_tty != nil
          return @force_tty
        end
        @tty
      end

      def terminal_width
        return @terminal_width if @terminal_width
        begin
          require 'io/console'
          width = $stdout.winsize[1]
        rescue LoadError, NoMethodError, Errno::ENOTTY, Errno::EBADF, Errno::EINVAL
          width = ENV["COLUMNS"].to_i.nonzero? || 80
        end
        width -= 1 if /mswin|mingw/ =~ RUBY_PLATFORM
        @terminal_width = width
        @terminal_width
      end

      def del_status_line(flush: true)
        if @options[:job_status] == :replace
          $stdout.print "\r"+" "*@status_line_size+"\r"
        else
          if @status_line_size > 0
            $stdout.puts
          elsif @options[:job_status] == :none && !@options[:parallel]
            $stdout.puts
          end
        end
        $stdout.flush if flush
        @status_line_size = 0
      end

      def jobs_status(worker: nil, except: nil)
        return if @options[:job_status] == :none
        if @options[:job_status] == :replace
          status_line = @workers.map(&:to_s).join(" ")
        elsif except
          status_line = (@workers-Array(except)).map(&:to_s).join(" ")
        else
          raise ArgumentError, "needs worker" unless worker
          status_line = worker.to_s
        end
        update_status(status_line) or (puts; nil)
      end

      def _prepare_run_suites(suites, type)
        raise if worker_process?
        @options[:job_status] ||= :replace if use_tty? && !@verbose
        @options[:job_status] ||= :normal
        case @options[:color]
        when :always
          color = true
        when :auto, nil
          color = true if use_tty? || @options[:job_status] == :replace
        else
          color = false
        end
        colors_file = File.expand_path(File.join(__dir__, "../../colors"))
        @colorize ||= Colorize.new(color, colors_file: colors_file)
        @output = Output.new(self) unless @options[:testing_parallel]
        filter = @options[:test_name_filter] || // # match anything
        type = "#{type}_methods"
        total = suites.inject(0) do |n, suite|
          n + suite.send(type).map { |test| "#{suite}##{test}" }.grep(filter).size
        end
        @test_count = 0
        @total_tests = total.to_s(10)
        @report.clear
      end

      def update_status(s, test_count: nil, total_tests: nil)
        return if @options[:job_status] == :none
        total_tests = total_tests || @total_tests.to_i
        test_count = test_count || @test_count
        count = test_count.to_s(10).rjust(total_tests.to_s.size)
        del_status_line(flush: false)
        add_status(@colorize.pass("[#{count}/#{total_tests}]"))
        add_status(" #{s}")
        $stdout.print "\r" if @options[:job_status] == :replace and !@verbose
        $stdout.flush
      end

      def setup_options(opts, options)
        super

        opts.separator "status line options:"

        options[:job_status] = nil
        options[:color] = :auto

        # 'normal': 1 new status line per suite
        # 'replace': line gets replaced every time it updates with new suite
        # 'none': no line is shown
        opts.on '--jobs-status [TYPE]', [:normal, :replace, :none],
                "Show status of jobs every file; Disabled when --jobs isn't specified." do |type|
          options[:job_status] = type
        end

        opts.on '--color[=WHEN]',
                [:always, :never, :auto],
                "colorize the output.  WHEN defaults to 'auto'", "or can be 'never' or 'always'." do |c|
          options[:color] = c
        end

        opts.on '--tty[=WHEN]',
                [:yes, :no],
                "force to output tty control.  WHEN defaults to 'yes'", "or can be 'no'." do |c|
          @tty = c != :no
          @force_tty = @tty
        end
      end

      class Output < Struct.new(:runner) # :nodoc: all
        def puts(*a) $stdout.puts(*a) unless a.empty? end
        def respond_to_missing?(*a) $stdout.respond_to?(*a) end
        def method_missing(*a, &b) $stdout.__send__(*a, &b) end

        NO_REPORT_CHANGE = [0,0,0]

        # Update status line of runner if `s` is in expected format,
        # returns number of [errors, failures, skips] that the message has
        def print(s)
          case s
          # Ex: "MyTest#test_something = "
          when /\A(.*\#.*) = \z/
            runner.new_test($1)
          # Ex: "0.63 s = "
          when /\A(.* s) = \z/
            runner.add_status(" = #$1")
          # Ex: "."
          when /\A\.+\z/
            runner.succeed
          # Ex: "F"
          when /\A\.*([EFS][EFS.]*)\z/
            efs = $1
            runner.failed(s, status: efs)
            return [efs.count('E'), efs.count('F'), efs.count('S')]
          else
            # Warnings, etc.
            $stdout.print(s)
          end
          NO_REPORT_CHANGE
        end

        def print_verbose(s, test_count: nil, total_tests: nil)
          case s
          # Ex: "MyTest#test_something = 0.50 s = ."
          when /\A(.+?) (= [0-9.]+ s) = ([EFS.])/
            efsp = $3
            match = $1
            time = $2
            _test = match =~ /(.+#.+)/
            runner.new_test($1, test_count: test_count, total_tests: total_tests)
            runner.add_status(time)
            if efsp == '.'
              runner.succeed
            else
              runner.failed(efsp, status: efsp)
              [efsp.count('F'), efsp.count('E'), efsp.count('S')]
            end
          else
            $stdout.print(s)
            NO_REPORT_CHANGE
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
        # Defaults to ($ruby_srcdir)/test
        parser.on '-B', '--base-directory DIR', 'Base directory to glob' do |dir|
          raise OptionParser::InvalidArgument, "not a directory: #{dir}" unless File.directory?(dir)
          if options[:base_directory]
            raise OptionParser::InvalidArgument, "Can't give multiple base directories"
          end
          dir = File.expand_path(dir) unless File.absolute_path?(dir)
          $LOAD_PATH.unshift(dir) unless $:.include?(dir)
          options[:base_directory] = dir
        end
        # example: -x test_hash
        parser.on '-x', '--exclude PATTERN', 'Exclude test files on basic pattern. Ex: -x test_gc' do |pattern|
          # NOTE: -x /test_hash/ does not work. This is not same format as --name option.
          if /\A\// =~ pattern && (!File.exist?(pattern) || pattern == '//')
            @option_warnings << "Warning: -x pattern should be a basic string pattern, / is treated as part of file path"
          end
          (options[:exclude_file_patterns] ||= []) << pattern
        end
      end

      def complement_test_name f, orig_f
        basename = File.basename(f)
        dirname = File.dirname(f)
        if /\.rb\z/ !~ basename
          if dirname == '.'
            return basename+'.rb'
          else
            return File.join(dirname, basename+'.rb')
          end
        elsif /\Atest_/ !~ basename
          if dirname == '.'
            return 'test_' + basename
          else
            return File.join(dirname, 'test_'+basename)
          end
        end if f.end_with?(basename) # otherwise basename is dirname/

        raise ArgumentError, "file not found: #{orig_f}"
      end

      # Gets list of files from base directory and given files. Changes input `files` array.
      def non_options(files, options)
        @orig_files = files.dup
        if worker_process?
          return super(files, options)
        end
        base_paths = [options[:base_directory], nil]
        if exclude_pats = options[:exclude_file_patterns]
          exclude_re = Regexp.union(exclude_pats.map {|r| %r"#{r}"})
        end
        if files != [base_paths[0]] && files.size >= 2
          files.delete base_paths[0]
          @orig_files.delete base_paths[0]
        end
        files.map! do |f|
          f = f.tr(File::ALT_SEPARATOR, File::SEPARATOR) if File::ALT_SEPARATOR
          orig_f = f
          while true
            found = base_paths.any? do |prefix|
              abs_file_no_prefix = false
              if prefix
                if File.absolute_path?(f)
                  path = f
                  abs_file_no_prefix = true
                else
                  # relative path
                  path =
                    if f.empty?
                      prefix
                    else
                      "#{prefix}/#{f}"
                    end
                end
              else
                next if f.empty?
                path = f
              end

              path_is_dir = Dir.exist?(path)
              dir = path_is_dir ? path : nil
              if dir
                match = (Dir["#{dir}/**/#{@@testfile_prefix}_*.rb"] + Dir["#{dir}/**/*_#{@@testfile_suffix}.rb"]).uniq
              else
                match = Dir[path]
              end

              if match.any?
                if exclude_pats
                  match.reject! {|n|
                    without_prefix = if abs_file_no_prefix
                      n
                    else
                      n[(prefix.length+1)..-1] if prefix
                    end
                    exclude_re =~ without_prefix
                  }
                end
                break match
              elsif !exclude_pats or (exclude_re !~ f and File.exist?(path))
                if !File.exist?(path)
                  next
                end
                break path
              else
                # no matches or file is excluded
                false
              end
            end # paths.any?

            if !found
              f = complement_test_name(f, orig_f)
            else
              break found
            end
          end # while
        end
        files.flatten!
        files.uniq!
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
        # This does not exclude directories from being run, it's a directory
        # that has special files that exclude tests from certain test classes.
        parser.on '-X', '--excludes-dir DIRECTORY', "Directory name of special exclude files" do |d|
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
        @suite_test_count = @suite_assertion_count = 0
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
      @@current_repeat_count = 0 # repeat count of all suites

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
          next if var == :@tasks # too big
          next if var == :@files # too big
          next if var == :@workers_hash # too big
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
        msg = format % [@test_count, @assertion_count, @failures, @errors, @skips]
        if self.class.current_repeat_count > 1 && @repeat_count == self.class.current_repeat_count
          msg << " (#{@repeat_count}/#{@repeat_count})"
        end
        io.puts msg
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

        puts "Run options:#{@help}"
        if @option_warnings.any?
          @option_warnings.each { |w| $stderr.puts "\n", w }
        end
        if req = @options.delete(:requirer)
          puts "\n# Loading test files"
          req.call
        end

        self.class.plugins.each do |plugin|
          send plugin
          break if @report.any?
        end

        return @failures + @errors if @test_count > 0 # or return nil
      rescue Interrupt
        abort 'Interrupted'
      end

      # Add error message to @report array, and update `@skips`, `@failures`, `@errors`
      # Returns string of length 1, one of: .|S|F|E|T
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
              err_class = ProxyError === e.class ? e.error_class : e.class.name
              "Error:\n#{klass}##{meth}:\n#{err_class}: #{e.message.b}\n    #{bt}\n"
            end
        @report << e
        rep = e[0, 1] # S|F|T|E
        if Test::Unit::PendedError === e and /no message given\z/ =~ e.message
          @report.slice!(n..-1) # skip without message, treat as pass
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

      def puts *a # :nodoc:
        output.puts(*a)
      end

      def print *a # :nodoc:
        output.print(*a)
      end

      def print_verbose *a, **kw # :nodoc:
        output.print_verbose(*a, **kw)
      end

      private


      def exit status = 0 # :nodoc:
        # stdout piped to file
        if !$stdout.tty? && !worker_process?
          $stdout.puts
          $stdout.puts "Exited with status #{status}"
        end
        super
      end

      def abort msg = "" # :nodoc:
        # stdout piped to file
        if !$stdout.tty? && !worker_process?
          $stdout.puts
          # Don't want to output the message twice (for instance, if 2>&1)
          $stdout.puts msg if $stderr.tty? && !msg.empty?
          $stdout.puts "Exited with status 1"
        end
        super
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
        test_count = assertion_count = 0 # includes repeat runs of suites
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
              [(@repeat_count ? " (#{@@current_repeat_count}/#{@repeat_count})" : ""), type,
               t, @test_count.fdiv(t), @assertion_count.fdiv(t)]
        end while @repeat_count && @@current_repeat_count < @repeat_count &&
                  @report.empty? && @failures.zero? && @errors.zero?

        output.sync = old_sync if sync

        output_error_messages

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

        use_leakchecker = true
        if defined?(RubyVM::MJIT) && RubyVM::MJIT.enabled? # compiler process is wrongly considered as leak
          use_leakchecker = false
        elsif @options[:without_leakchecker] || (worker_process? && @options[:silence_worker_output])
          use_leakchecker = false
        end

        unless use_leakchecker
          leakchecker = LeakChecker.new(output: self.class.output, use_buffered_output: worker_process?)
        end
        if ENV["LEAK_CHECKER_TRACE_OBJECT_ALLOCATION"]
          require "objspace"
          trace = true
        end

        @suite_test_count = 0
        @suite_assertion_count = 0
        all_test_methods.each { |method|
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
          @suite_test_count += 1
          @last_test_assertions = inst._assertions

          print "%.2f s = " % (Time.now - start_time) if @verbose
          print result # single character
          puts if @verbose
          self.output.flush

          unless use_leakchecker
            leakchecker.check("#{inst.class}\##{inst.__name__}")
          end

          _end_method(inst)

          @suite_assertion_count += inst._assertions
        }
        return [@suite_test_count, @suite_assertion_count]
      end

      def _start_method(inst) # :nodoc:
      end

      def _end_method(inst) # :nodoc:
      end

      ##
      # For performance reasons, records are not always sent across processes
      # in parallel mode. If you need records in parallel mode, you must override this.

      def recording?
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
          if !options[:base_directory]
            base = options[:base_directory] = default_dir
            $LOAD_PATH.unshift base
          else
            base = options[:base_directory]
          end
          base = File.absolute_path?(base) ? base : File.expand_path(base)
          files << base
          @to_run = files
          yield self if block_given?
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
          $stderr.puts "No test files to run!"
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
      attr_reader :message, :backtrace, :error_class

      def initialize(ex, msg = nil)
        @message = msg || ex.message
        @backtrace = ex.backtrace
        @error_class = ex.class.name
      end
    end
  end
end

Test::Unit::Runner.autorun

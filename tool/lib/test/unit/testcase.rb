# frozen_string_literal: true
require_relative 'assertions'
require_relative '../../core_assertions'

module Test
  module Unit

    ##
    # Provides a simple set of guards that you can use in your tests
    # to skip execution if it is not applicable. These methods are
    # mixed into TestCase as both instance and class methods so you
    # can use them inside or outside of the test methods.
    #
    #   def test_something_for_mri
    #     skip "bug 1234"  if jruby?
    #     # ...
    #   end
    #
    #   if windows? then
    #     # ... lots of test methods ...
    #   end

    module Guard

      ##
      # Is this running on jruby?

      def jruby? platform = RUBY_PLATFORM
        "java" == platform
      end

      ##
      # Is this running on mri?

      def mri? platform = RUBY_DESCRIPTION
        /^ruby/ =~ platform
      end

      ##
      # Is this running on windows?

      def windows? platform = RUBY_PLATFORM
        /mswin|mingw/ =~ platform
      end

      ##
      # Is this running on mingw?

      def mingw? platform = RUBY_PLATFORM
        /mingw/ =~ platform
      end

    end

    ##
    # Provides before/after hooks for setup and teardown. These are
    # meant for library writers, NOT for regular test authors. See
    # #before_setup for an example.

    module LifecycleHooks
      ##
      # Runs before every test, after setup. This hook is meant for
      # libraries to extend Test::Unit. It is not meant to be used by
      # test developers.
      #
      # See #before_setup for an example.

      def after_setup; end

      ##
      # Runs before every test, before setup. This hook is meant for
      # libraries to extend Test::Unit. It is not meant to be used by
      # test developers.
      #
      # As a simplistic example:
      #
      #   module MyTestUnitPlugin
      #     def before_setup
      #       super
      #       # ... stuff to do before setup is run
      #     end
      #
      #     def after_setup
      #       # ... stuff to do after setup is run
      #       super
      #     end
      #
      #     def before_teardown
      #       super
      #       # ... stuff to do before teardown is run
      #     end
      #
      #     def after_teardown
      #       # ... stuff to do after teardown is run
      #       super
      #     end
      #   end
      #
      #   class Test::Unit::Runner::TestCase
      #     include MyTestUnitPlugin
      #   end

      def before_setup; end

      ##
      # Runs after every test, before teardown. This hook is meant for
      # libraries to extend Test::Unit. It is not meant to be used by
      # test developers.
      #
      # See #before_setup for an example.

      def before_teardown; end

      ##
      # Runs after every test, after teardown. This hook is meant for
      # libraries to extend Test::Unit. It is not meant to be used by
      # test developers.
      #
      # See #before_setup for an example.

      def after_teardown; end
    end

    ##
    # Subclass TestCase to create your own tests. Typically you'll want a
    # TestCase subclass per implementation class.
    #
    # See <code>Test::Unit::AssertionFailedError</code>s

    class TestCase
      include Assertions
      include CoreAssertions

      include LifecycleHooks
      include Guard
      extend Guard

      attr_reader :__name__ # :nodoc:

      PASSTHROUGH_EXCEPTIONS = [NoMemoryError, SignalException,
                                Interrupt, SystemExit] # :nodoc:
      TEARDOWN_HOOKS = [:before_teardown, :teardown, :after_teardown]

      # Run a single test method.
      # Returns string of length 1, one of: .|S|F|E|T
      def run runner
        trap "INFO" do
          _on_info_signal_during_run(runner)
        end if runner.info_signal && !on_parallel_worker?

        start_time = Time.now

        result = ""

        begin
          @_passed = nil
          @_interrupted = nil
          self.before_setup
          self.setup
          self.after_setup
          self._run_test @__name__
          result = "." unless __io__?
          time = Time.now - start_time
          runner.record self.class, @__name__, @_assertions, time, nil
          @_passed = true
        rescue *PASSTHROUGH_EXCEPTIONS => e
          @_interrupted = e if e.is_a?(Interrupt)
          raise
        rescue Exception => e
          @_passed = Test::Unit::PendedError === e
          time = Time.now - start_time
          runner.record self.class, @__name__, @_assertions, time, e
          result = runner.puke self.class, @__name__, e
        ensure
          # If we run the teardown hooks after an interrupt, we get lots of errors
          unless @_interrupted
            TEARDOWN_HOOKS.each do |hook|
              begin
                self.send hook
              rescue *PASSTHROUGH_EXCEPTIONS
                raise
              rescue Exception => e
                @_passed = false
                runner.record self.class, @__name__, @_assertions, time, e
                result = runner.puke self.class, @__name__, e
              end
            end
          end
          trap 'INFO', 'DEFAULT' if runner.info_signal && !on_parallel_worker?
        end
        result
      end

      RUN_TEST_TRACE = "#{__FILE__}:#{__LINE__+3}:in `run_test'".freeze
      def _run_test(name)
        progname, $0 = $0, "#{$0}: #{self.class}##{name}"
        self.__send__(name)
      ensure
        $@.delete(RUN_TEST_TRACE) if $@
        $0 = progname
      end

      def initialize name # :nodoc:
        @__name__ = name
        @__io__ = false
        @_passed = nil
        @_assertions = 0
        @@current = self # FIX: make thread local
      end

      # Return the output IO object

      def __io__
        @__io__ = true
        Test::Unit::Runner.output
      end

      ##
      # Have we hooked up the IO yet?

      def __io__?
        @__io__
      end

      def self.current # :nodoc:
        @@current # FIX: make thread local
      end

      def self.reset # :nodoc:
        @@test_suites = {}
        @@test_suites[self] = true
      end
      reset

      def self.inherited klass # :nodoc:
        @@test_suites[klass] = true
        klass.instance_variable_set("@test_methods", {})
        super
      end

      @test_order = :sorted

      class << self
        attr_writer :test_order
      end

      def self.test_order
        defined?(@test_order) ? @test_order : superclass.test_order
      end

      def self.test_suites # :nodoc:
        @@test_suites.keys
      end

      def self.test_methods # :nodoc:
        public_instance_methods(true).grep(/^test_/)
      end

      def self.method_added(name)
        super
        return unless name.to_s.start_with?("test_")
        if @test_methods[name]
          raise AssertionFailedError, "test/unit: method #{self}##{name} is redefined"
        end
        @test_methods[name] = true
      end

      ##
      # Returns true if the test passed.

      def passed?
        @_passed
      end

      ##
      # Runs before every test. Use this to set up before each test
      # run.

      def setup; end

      ##
      # Runs after every test. Use this to clean up after each test
      # run.

      def teardown; end

      def on_parallel_worker?
        false
      end

      private

      def _on_info_signal_during_run(runner)
        runner.report.each_with_index do |msg, i|
          warn "\n%3d) %s" % [i + 1, msg]
        end
        warn ''
        time = runner.start_time ? Time.now - runner.start_time : 0
        warn "Current Test: %s#%s %.2fs" % [self.class, @__name__, time]
        runner.status $stderr
      end
    end
  end
end

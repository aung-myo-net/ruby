# frozen_string_literal: true
require 'test/unit'

class TestRactor < Test::Unit::TestCase
  def test_no_thread_creation_during_new_with_args
    klass = EnvUtil.labeled_class(:MyObject) do
      attr_accessor :unshareable
      def initialize_clone(orig)
        Thread.new do
          self.unshareable = orig
        end
        super(orig)
      end
    end
    obj = klass.new

    prev_count = Ractor.count
    e = nil
    begin
      r = Ractor.new(obj) {}
    rescue => e
    else
      r.take
    end
    assert_kind_of(ThreadError, e)
    assert_equal prev_count, Ractor.count
    assert_equal :can_create, Thread.new { :can_create }.join.value
  end

  def test_no_thread_creation_during_send
    klass = EnvUtil.labeled_class(:MyObject) do
      attr_accessor :unshareable
      def initialize_clone(orig)
        Thread.new do
          self.unshareable = orig
        end
        super(orig)
      end
    end
    obj = klass.new

    e = nil
    r = Ractor.new { receive; :end }
    begin
      r.send(obj)
    rescue => e
    end
    assert_kind_of(ThreadError, e)
    r.send(:hi)
    raise "bad ending" unless r.take == :end
    assert_equal :can_create, Thread.new { :can_create }.join.value
  end
end

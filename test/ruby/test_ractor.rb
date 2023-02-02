# frozen_string_literal: true
require 'test/unit'
require 'stringio'
require 'csv'
require 'monitor'
require 'ostruct'

class TestRactor < Test::Unit::TestCase
  def setup_receiver_ractor
    raise ArgumentError unless block_given?
    ractor = Ractor.new do
      loop do
        v = Ractor.receive
        if v == :end
          break
        end
      end
      :ok
    end
    begin
      yield ractor
    rescue => e
      ractor << :end
      raise "bad ending" unless ractor.take == :ok
      raise e
    end
  end
  def setup_echo_ractor
    raise ArgumentError unless block_given?
    ractor = Ractor.new do
      loop do
        v = Ractor.receive
        if v == :end
          break
        end
        Ractor.yield v
      end
      :ok
    end
    begin
      yield ractor
    rescue => e
      ractor << :end
      raise "bad ending" unless ractor.take == :ok
      raise e
    end
  end

  def test_shareable_objects
    c_class = EnvUtil.labeled_class(:C)
    m_mod = Module.new { }
    struct_class = Struct.new(:a, :b, :c, :d)
    shareable_objects = [
      true,
      false,
      nil,
      1,
      1.1,    # Float
      1+2r,   # Rational
      3+4i,   # Complex
      2**128, # Bignum
      :sym,   # Symbol
      'xyzzy'.to_sym, # dynamic symbol
      'frozen'.freeze, # frozen String
      /regexp/, # regexp literal
      /reg{true}exp/.freeze, # frozen dregexp
      [1, 2].freeze,   # frozen Array which only refers to shareable
      {a: 1}.freeze,   # frozen Hash which only refers to shareable
      [{a: 1}.freeze, 'str'.freeze].freeze, # nested frozen container
      struct_class.new(1, 2).freeze, # frozen Struct
      struct_class.new(1, 2, 3, 4).freeze, # frozen Struct
      (1..2), # Range
      (1..),  # Range
      (..1),  # Range
      c_class, # class
      m_mod, # module
      Ractor.current, # Ractor
    ]
    setup_echo_ractor do |ractor|
      shareable_objects.each do |obj|
        assert Ractor.shareable?(obj)
        ractor << obj
        obj2 = ractor.take
        assert_equal obj.object_id, obj2.object_id, "#{obj.class} not same object after send (#{obj.inspect} => #{obj2.inspect})"
      end
    end
  end

  ## More of these types of tests are in the btest suite.
  ## These are just checking extension classes.
  def test_unshareable_but_copyable_objects_for_send
    setup_echo_ractor do |ractor|
      struct_class = Struct.new(:a, :b, :c, :d)
      unshareable_but_copyable_objects = [
        'mutable str'.dup,
          [:array],
          {hash: true},
          struct_class.new(1, 2),
          struct_class.new(1, 2, 3, 4),
          struct_class.new("a".dup, 2).freeze, # frozen, but refers to an unshareable object
          OpenStruct.new,
          Exception.new,
          Time.now,
      ]
      unshareable_but_copyable_objects.each do |o|
        refute Ractor.shareable?(o), "#{o} shouldn't be greenlit as shareable"
        ractor << o
        o2 = ractor.take
        assert_not_equal o.object_id, o2.object_id, "#{o.class} is not copying"
      end
    end
  end
  ## More of these types of tests are in the btest suite.
  ## These are just checking extension classes.
  def test_unshareable_non_copyable_objects_for_send
    th = nil
    setup_receiver_ractor do |ractor|
      unshareable_non_copyable_objects = [
        Kernel.instance_method(:to_s),
        #Kernel.instance_method(:to_s).bind(self), # FIXME: crashing
        binding,
        lambda { }, # refers to non-shareable self
        proc { }, # refers to non-shareable self
        (th = Thread.new { }),
        TracePoint.new { },
        #Fiber.new { } # FIXME: currently can send
        #StringIO.new(string),
        #CSV.new(string),
        #Monitor.new,
        # TODO:
        # check Net::HTTP
        # check Logger
        # check URI
        # check Socket
        # check Pathname
        # check JSON::Parser
        # check ERB
        # check Date
        # check CSV
      ]
      setup_receiver_ractor do |ractor|
        unshareable_non_copyable_objects.each do |o|
          refute Ractor.shareable?(o), "#{o} shouldn't be greenlit as shareable"
          e = nil
          begin
            ractor << o
          rescue TypeError, Ractor::Error => e
          end
          assert_kind_of(Exception, e, "#{o} shouldn't be cloneable for Ractor#send")
        end
      end
    end
  ensure
    th.join if th
  end

  def test_fork_after_ractor_creation
    r1 = Ractor.new do
    end
    r2 = Ractor.new do
    end
    pid = fork do
      exit Ractor.count
    end
    _pid, status = Process.waitpid2(pid)
    assert_equal 1, status.exitstatus
    r1.take
    r2.take
  end

  def test_fork_in_ractor
    r1 = Ractor.new do
      pid = fork do
        exit 0
      end
      pid
    end
    pid = r1.take
    _pid, status = Process.waitpid2(pid)
    assert_equal 0, status.exitstatus
  end
end

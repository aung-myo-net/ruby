# frozen_string_literal: true

module ZombieHunter
  def after_teardown
    super
    assert_empty(Process.waitall)
  end
end

unless ENV['RUBY_TEST_NO_CHECKERS']
  Test::Unit::TestCase.include ZombieHunter
end

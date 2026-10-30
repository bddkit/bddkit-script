Feature: Script steps

  Scenario: a script derives a value from the file's variables
    Given set variable "user" to "Ann"
    When I execute script to "greeting":
      """
      `hello ${vars.user}`
      """
    Then variable "greeting" should be equal to "hello Ann"

  Scenario: a map becomes several variables
    When I execute script to variables:
      """
      #{ token: "t", user: #{ name: "Ann" } }
      """
    Then variable "token" should be equal to "t"
    And variable "user_name" should be equal to "Ann"

rule TTP_XOR_MULT_DOSStub_34ff {
  strings:
    $key_34ff = { 60 97 [2] 14 8f [2] 53 8d [2] 14 9c [2] 5a 90 [2] 56 9a [2] 41 91 [2] 5a df [2] 67 }

  condition:
    any of them
}
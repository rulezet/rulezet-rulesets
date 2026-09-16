rule TTP_XOR_MULT_DOSStub_55ff {
  strings:
    $key_55ff = { 01 97 [2] 75 8f [2] 32 8d [2] 75 9c [2] 3b 90 [2] 37 9a [2] 20 91 [2] 3b df [2] 06 }

  condition:
    any of them
}
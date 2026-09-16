rule TTP_XOR_MULT_DOSStub_75ff {
  strings:
    $key_75ff = { 21 97 [2] 55 8f [2] 12 8d [2] 55 9c [2] 1b 90 [2] 17 9a [2] 00 91 [2] 1b df [2] 26 }

  condition:
    any of them
}
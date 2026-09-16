rule TTP_XOR_MULT_DOSStub_5915 {
  strings:
    $key_5915 = { 0d 7d [2] 79 65 [2] 3e 67 [2] 79 76 [2] 37 7a [2] 3b 70 [2] 2c 7b [2] 37 35 [2] 0a }

  condition:
    any of them
}
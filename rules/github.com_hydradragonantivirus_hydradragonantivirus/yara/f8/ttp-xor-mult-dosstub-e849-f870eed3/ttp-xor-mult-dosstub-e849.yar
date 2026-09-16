rule TTP_XOR_MULT_DOSStub_e849 {
  strings:
    $key_e849 = { bc 21 [2] c8 39 [2] 8f 3b [2] c8 2a [2] 86 26 [2] 8a 2c [2] 9d 27 [2] 86 69 [2] bb }

  condition:
    any of them
}
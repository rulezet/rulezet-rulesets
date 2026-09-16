rule TTP_XOR_MULT_DOSStub_e449 {
  strings:
    $key_e449 = { b0 21 [2] c4 39 [2] 83 3b [2] c4 2a [2] 8a 26 [2] 86 2c [2] 91 27 [2] 8a 69 [2] b7 }

  condition:
    any of them
}
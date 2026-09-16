rule TTP_XOR_MULT_DOSStub_e749 {
  strings:
    $key_e749 = { b3 21 [2] c7 39 [2] 80 3b [2] c7 2a [2] 89 26 [2] 85 2c [2] 92 27 [2] 89 69 [2] b4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e445 {
  strings:
    $key_e445 = { b0 2d [2] c4 35 [2] 83 37 [2] c4 26 [2] 8a 2a [2] 86 20 [2] 91 2b [2] 8a 65 [2] b7 }

  condition:
    any of them
}
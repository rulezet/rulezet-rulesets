rule TTP_XOR_MULT_DOSStub_e448 {
  strings:
    $key_e448 = { b0 20 [2] c4 38 [2] 83 3a [2] c4 2b [2] 8a 27 [2] 86 2d [2] 91 26 [2] 8a 68 [2] b7 }

  condition:
    any of them
}
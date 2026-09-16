rule TTP_XOR_MULT_DOSStub_e345 {
  strings:
    $key_e345 = { b7 2d [2] c3 35 [2] 84 37 [2] c3 26 [2] 8d 2a [2] 81 20 [2] 96 2b [2] 8d 65 [2] b0 }

  condition:
    any of them
}
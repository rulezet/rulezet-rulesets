rule TTP_XOR_MULT_DOSStub_e658 {
  strings:
    $key_e658 = { b2 30 [2] c6 28 [2] 81 2a [2] c6 3b [2] 88 37 [2] 84 3d [2] 93 36 [2] 88 78 [2] b5 }

  condition:
    any of them
}
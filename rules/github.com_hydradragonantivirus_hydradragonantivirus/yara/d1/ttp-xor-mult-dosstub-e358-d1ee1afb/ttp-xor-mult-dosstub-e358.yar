rule TTP_XOR_MULT_DOSStub_e358 {
  strings:
    $key_e358 = { b7 30 [2] c3 28 [2] 84 2a [2] c3 3b [2] 8d 37 [2] 81 3d [2] 96 36 [2] 8d 78 [2] b0 }

  condition:
    any of them
}
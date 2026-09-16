rule TTP_XOR_MULT_DOSStub_c058 {
  strings:
    $key_c058 = { 94 30 [2] e0 28 [2] a7 2a [2] e0 3b [2] ae 37 [2] a2 3d [2] b5 36 [2] ae 78 [2] 93 }

  condition:
    any of them
}
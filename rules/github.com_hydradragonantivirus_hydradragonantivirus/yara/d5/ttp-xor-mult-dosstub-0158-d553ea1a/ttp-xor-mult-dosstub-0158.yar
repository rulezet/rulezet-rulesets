rule TTP_XOR_MULT_DOSStub_0158 {
  strings:
    $key_0158 = { 55 30 [2] 21 28 [2] 66 2a [2] 21 3b [2] 6f 37 [2] 63 3d [2] 74 36 [2] 6f 78 [2] 52 }

  condition:
    any of them
}
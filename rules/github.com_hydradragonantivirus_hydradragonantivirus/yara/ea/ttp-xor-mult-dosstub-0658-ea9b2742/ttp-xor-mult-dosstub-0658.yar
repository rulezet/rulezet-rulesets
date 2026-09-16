rule TTP_XOR_MULT_DOSStub_0658 {
  strings:
    $key_0658 = { 52 30 [2] 26 28 [2] 61 2a [2] 26 3b [2] 68 37 [2] 64 3d [2] 73 36 [2] 68 78 [2] 55 }

  condition:
    any of them
}
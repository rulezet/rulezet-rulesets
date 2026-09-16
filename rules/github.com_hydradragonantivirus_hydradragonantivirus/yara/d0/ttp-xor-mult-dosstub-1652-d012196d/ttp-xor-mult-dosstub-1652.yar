rule TTP_XOR_MULT_DOSStub_1652 {
  strings:
    $key_1652 = { 42 3a [2] 36 22 [2] 71 20 [2] 36 31 [2] 78 3d [2] 74 37 [2] 63 3c [2] 78 72 [2] 45 }

  condition:
    any of them
}
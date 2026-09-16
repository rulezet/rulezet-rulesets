rule TTP_XOR_MULT_DOSStub_3052 {
  strings:
    $key_3052 = { 64 3a [2] 10 22 [2] 57 20 [2] 10 31 [2] 5e 3d [2] 52 37 [2] 45 3c [2] 5e 72 [2] 63 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0152 {
  strings:
    $key_0152 = { 55 3a [2] 21 22 [2] 66 20 [2] 21 31 [2] 6f 3d [2] 63 37 [2] 74 3c [2] 6f 72 [2] 52 }

  condition:
    any of them
}
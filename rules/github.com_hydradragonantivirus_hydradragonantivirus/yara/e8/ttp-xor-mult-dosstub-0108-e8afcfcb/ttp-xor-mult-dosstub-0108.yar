rule TTP_XOR_MULT_DOSStub_0108 {
  strings:
    $key_0108 = { 55 60 [2] 21 78 [2] 66 7a [2] 21 6b [2] 6f 67 [2] 63 6d [2] 74 66 [2] 6f 28 [2] 52 }

  condition:
    any of them
}
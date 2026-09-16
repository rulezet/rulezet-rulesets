rule TTP_XOR_MULT_DOSStub_4648 {
  strings:
    $key_4648 = { 12 20 [2] 66 38 [2] 21 3a [2] 66 2b [2] 28 27 [2] 24 2d [2] 33 26 [2] 28 68 [2] 15 }

  condition:
    any of them
}
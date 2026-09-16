rule TTP_XOR_MULT_DOSStub_4148 {
  strings:
    $key_4148 = { 15 20 [2] 61 38 [2] 26 3a [2] 61 2b [2] 2f 27 [2] 23 2d [2] 34 26 [2] 2f 68 [2] 12 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3148 {
  strings:
    $key_3148 = { 65 20 [2] 11 38 [2] 56 3a [2] 11 2b [2] 5f 27 [2] 53 2d [2] 44 26 [2] 5f 68 [2] 62 }

  condition:
    any of them
}
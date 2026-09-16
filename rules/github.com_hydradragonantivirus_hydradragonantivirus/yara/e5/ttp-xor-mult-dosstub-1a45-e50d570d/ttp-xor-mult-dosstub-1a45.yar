rule TTP_XOR_MULT_DOSStub_1a45 {
  strings:
    $key_1a45 = { 4e 2d [2] 3a 35 [2] 7d 37 [2] 3a 26 [2] 74 2a [2] 78 20 [2] 6f 2b [2] 74 65 [2] 49 }

  condition:
    any of them
}
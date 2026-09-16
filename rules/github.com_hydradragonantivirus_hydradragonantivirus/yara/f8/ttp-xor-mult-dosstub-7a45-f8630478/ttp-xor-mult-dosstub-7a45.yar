rule TTP_XOR_MULT_DOSStub_7a45 {
  strings:
    $key_7a45 = { 2e 2d [2] 5a 35 [2] 1d 37 [2] 5a 26 [2] 14 2a [2] 18 20 [2] 0f 2b [2] 14 65 [2] 29 }

  condition:
    any of them
}
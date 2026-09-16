rule TTP_XOR_MULT_DOSStub_4d45 {
  strings:
    $key_4d45 = { 19 2d [2] 6d 35 [2] 2a 37 [2] 6d 26 [2] 23 2a [2] 2f 20 [2] 38 2b [2] 23 65 [2] 1e }

  condition:
    any of them
}
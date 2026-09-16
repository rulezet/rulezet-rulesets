rule TTP_XOR_MULT_DOSStub_4af5 {
  strings:
    $key_4af5 = { 1e 9d [2] 6a 85 [2] 2d 87 [2] 6a 96 [2] 24 9a [2] 28 90 [2] 3f 9b [2] 24 d5 [2] 19 }

  condition:
    any of them
}
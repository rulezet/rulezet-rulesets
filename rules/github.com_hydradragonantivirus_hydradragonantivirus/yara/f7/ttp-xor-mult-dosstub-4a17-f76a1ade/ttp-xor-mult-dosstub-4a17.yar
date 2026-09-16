rule TTP_XOR_MULT_DOSStub_4a17 {
  strings:
    $key_4a17 = { 1e 7f [2] 6a 67 [2] 2d 65 [2] 6a 74 [2] 24 78 [2] 28 72 [2] 3f 79 [2] 24 37 [2] 19 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4a37 {
  strings:
    $key_4a37 = { 1e 5f [2] 6a 47 [2] 2d 45 [2] 6a 54 [2] 24 58 [2] 28 52 [2] 3f 59 [2] 24 17 [2] 19 }

  condition:
    any of them
}
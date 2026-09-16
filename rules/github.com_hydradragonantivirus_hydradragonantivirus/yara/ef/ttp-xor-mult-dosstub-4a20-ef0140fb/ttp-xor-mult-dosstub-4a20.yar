rule TTP_XOR_MULT_DOSStub_4a20 {
  strings:
    $key_4a20 = { 1e 48 [2] 6a 50 [2] 2d 52 [2] 6a 43 [2] 24 4f [2] 28 45 [2] 3f 4e [2] 24 00 [2] 19 }

  condition:
    any of them
}
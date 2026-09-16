rule TTP_XOR_MULT_DOSStub_5107 {
  strings:
    $key_5107 = { 05 6f [2] 71 77 [2] 36 75 [2] 71 64 [2] 3f 68 [2] 33 62 [2] 24 69 [2] 3f 27 [2] 02 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4107 {
  strings:
    $key_4107 = { 15 6f [2] 61 77 [2] 26 75 [2] 61 64 [2] 2f 68 [2] 23 62 [2] 34 69 [2] 2f 27 [2] 12 }

  condition:
    any of them
}
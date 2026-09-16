rule TTP_XOR_MULT_DOSStub_5207 {
  strings:
    $key_5207 = { 06 6f [2] 72 77 [2] 35 75 [2] 72 64 [2] 3c 68 [2] 30 62 [2] 27 69 [2] 3c 27 [2] 01 }

  condition:
    any of them
}
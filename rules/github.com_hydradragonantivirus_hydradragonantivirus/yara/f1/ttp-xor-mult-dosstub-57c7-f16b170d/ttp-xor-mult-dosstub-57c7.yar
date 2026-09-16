rule TTP_XOR_MULT_DOSStub_57c7 {
  strings:
    $key_57c7 = { 03 af [2] 77 b7 [2] 30 b5 [2] 77 a4 [2] 39 a8 [2] 35 a2 [2] 22 a9 [2] 39 e7 [2] 04 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5786 {
  strings:
    $key_5786 = { 03 ee [2] 77 f6 [2] 30 f4 [2] 77 e5 [2] 39 e9 [2] 35 e3 [2] 22 e8 [2] 39 a6 [2] 04 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0276 {
  strings:
    $key_0276 = { 56 1e [2] 22 06 [2] 65 04 [2] 22 15 [2] 6c 19 [2] 60 13 [2] 77 18 [2] 6c 56 [2] 51 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4470 {
  strings:
    $key_4470 = { 10 18 [2] 64 00 [2] 23 02 [2] 64 13 [2] 2a 1f [2] 26 15 [2] 31 1e [2] 2a 50 [2] 17 }

  condition:
    any of them
}
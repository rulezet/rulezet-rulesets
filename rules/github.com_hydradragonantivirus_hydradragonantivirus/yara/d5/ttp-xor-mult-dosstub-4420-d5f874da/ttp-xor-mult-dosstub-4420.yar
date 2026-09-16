rule TTP_XOR_MULT_DOSStub_4420 {
  strings:
    $key_4420 = { 10 48 [2] 64 50 [2] 23 52 [2] 64 43 [2] 2a 4f [2] 26 45 [2] 31 4e [2] 2a 00 [2] 17 }

  condition:
    any of them
}
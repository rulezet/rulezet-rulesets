rule TTP_XOR_MULT_DOSStub_3470 {
  strings:
    $key_3470 = { 60 18 [2] 14 00 [2] 53 02 [2] 14 13 [2] 5a 1f [2] 56 15 [2] 41 1e [2] 5a 50 [2] 67 }

  condition:
    any of them
}
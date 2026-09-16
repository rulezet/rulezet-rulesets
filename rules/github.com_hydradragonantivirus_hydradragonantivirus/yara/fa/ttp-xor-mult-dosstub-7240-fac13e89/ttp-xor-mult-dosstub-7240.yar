rule TTP_XOR_MULT_DOSStub_7240 {
  strings:
    $key_7240 = { 26 28 [2] 52 30 [2] 15 32 [2] 52 23 [2] 1c 2f [2] 10 25 [2] 07 2e [2] 1c 60 [2] 21 }

  condition:
    any of them
}
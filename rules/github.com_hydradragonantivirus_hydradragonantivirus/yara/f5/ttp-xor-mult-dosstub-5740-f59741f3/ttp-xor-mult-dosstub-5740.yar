rule TTP_XOR_MULT_DOSStub_5740 {
  strings:
    $key_5740 = { 03 28 [2] 77 30 [2] 30 32 [2] 77 23 [2] 39 2f [2] 35 25 [2] 22 2e [2] 39 60 [2] 04 }

  condition:
    any of them
}
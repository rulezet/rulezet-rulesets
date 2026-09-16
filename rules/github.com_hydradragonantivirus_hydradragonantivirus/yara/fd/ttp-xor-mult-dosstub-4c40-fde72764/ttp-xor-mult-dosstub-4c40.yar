rule TTP_XOR_MULT_DOSStub_4c40 {
  strings:
    $key_4c40 = { 18 28 [2] 6c 30 [2] 2b 32 [2] 6c 23 [2] 22 2f [2] 2e 25 [2] 39 2e [2] 22 60 [2] 1f }

  condition:
    any of them
}
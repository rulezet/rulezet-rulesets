rule TTP_XOR_MULT_DOSStub_4451 {
  strings:
    $key_4451 = { 10 39 [2] 64 21 [2] 23 23 [2] 64 32 [2] 2a 3e [2] 26 34 [2] 31 3f [2] 2a 71 [2] 17 }

  condition:
    any of them
}
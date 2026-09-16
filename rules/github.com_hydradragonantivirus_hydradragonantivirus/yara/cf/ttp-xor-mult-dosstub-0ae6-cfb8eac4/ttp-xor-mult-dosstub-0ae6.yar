rule TTP_XOR_MULT_DOSStub_0ae6 {
  strings:
    $key_0ae6 = { 5e 8e [2] 2a 96 [2] 6d 94 [2] 2a 85 [2] 64 89 [2] 68 83 [2] 7f 88 [2] 64 c6 [2] 59 }

  condition:
    any of them
}
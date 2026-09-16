rule TTP_XOR_MULT_DOSStub_1001 {
  strings:
    $key_1001 = { 44 69 [2] 30 71 [2] 77 73 [2] 30 62 [2] 7e 6e [2] 72 64 [2] 65 6f [2] 7e 21 [2] 43 }

  condition:
    any of them
}
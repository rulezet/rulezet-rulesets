rule TTP_XOR_MULT_DOSStub_3001 {
  strings:
    $key_3001 = { 64 69 [2] 10 71 [2] 57 73 [2] 10 62 [2] 5e 6e [2] 52 64 [2] 45 6f [2] 5e 21 [2] 63 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0640 {
  strings:
    $key_0640 = { 52 28 [2] 26 30 [2] 61 32 [2] 26 23 [2] 68 2f [2] 64 25 [2] 73 2e [2] 68 60 [2] 55 }

  condition:
    any of them
}
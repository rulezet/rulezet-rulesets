rule TTP_XOR_MULT_DOSStub_4501 {
  strings:
    $key_4501 = { 11 69 [2] 65 71 [2] 22 73 [2] 65 62 [2] 2b 6e [2] 27 64 [2] 30 6f [2] 2b 21 [2] 16 }

  condition:
    any of them
}
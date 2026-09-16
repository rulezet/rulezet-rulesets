rule TTP_XOR_MULT_DOSStub_5501 {
  strings:
    $key_5501 = { 01 69 [2] 75 71 [2] 32 73 [2] 75 62 [2] 3b 6e [2] 37 64 [2] 20 6f [2] 3b 21 [2] 06 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0701 {
  strings:
    $key_0701 = { 53 69 [2] 27 71 [2] 60 73 [2] 27 62 [2] 69 6e [2] 65 64 [2] 72 6f [2] 69 21 [2] 54 }

  condition:
    any of them
}
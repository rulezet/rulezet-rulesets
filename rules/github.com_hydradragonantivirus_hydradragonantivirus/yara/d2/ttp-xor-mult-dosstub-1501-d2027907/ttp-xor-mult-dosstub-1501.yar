rule TTP_XOR_MULT_DOSStub_1501 {
  strings:
    $key_1501 = { 41 69 [2] 35 71 [2] 72 73 [2] 35 62 [2] 7b 6e [2] 77 64 [2] 60 6f [2] 7b 21 [2] 46 }

  condition:
    any of them
}
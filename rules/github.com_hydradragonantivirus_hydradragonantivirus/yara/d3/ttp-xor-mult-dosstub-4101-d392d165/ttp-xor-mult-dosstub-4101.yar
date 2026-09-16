rule TTP_XOR_MULT_DOSStub_4101 {
  strings:
    $key_4101 = { 15 69 [2] 61 71 [2] 26 73 [2] 61 62 [2] 2f 6e [2] 23 64 [2] 34 6f [2] 2f 21 [2] 12 }

  condition:
    any of them
}
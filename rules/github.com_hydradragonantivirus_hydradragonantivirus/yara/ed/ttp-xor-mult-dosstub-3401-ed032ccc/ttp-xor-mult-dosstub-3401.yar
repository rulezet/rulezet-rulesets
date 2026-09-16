rule TTP_XOR_MULT_DOSStub_3401 {
  strings:
    $key_3401 = { 60 69 [2] 14 71 [2] 53 73 [2] 14 62 [2] 5a 6e [2] 56 64 [2] 41 6f [2] 5a 21 [2] 67 }

  condition:
    any of them
}
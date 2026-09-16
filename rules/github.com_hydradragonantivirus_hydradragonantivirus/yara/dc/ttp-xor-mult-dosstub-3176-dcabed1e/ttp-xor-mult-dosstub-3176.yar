rule TTP_XOR_MULT_DOSStub_3176 {
  strings:
    $key_3176 = { 65 1e [2] 11 06 [2] 56 04 [2] 11 15 [2] 5f 19 [2] 53 13 [2] 44 18 [2] 5f 56 [2] 62 }

  condition:
    any of them
}
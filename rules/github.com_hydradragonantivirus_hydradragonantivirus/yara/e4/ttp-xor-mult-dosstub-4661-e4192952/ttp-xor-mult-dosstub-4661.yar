rule TTP_XOR_MULT_DOSStub_4661 {
  strings:
    $key_4661 = { 12 09 [2] 66 11 [2] 21 13 [2] 66 02 [2] 28 0e [2] 24 04 [2] 33 0f [2] 28 41 [2] 15 }

  condition:
    any of them
}
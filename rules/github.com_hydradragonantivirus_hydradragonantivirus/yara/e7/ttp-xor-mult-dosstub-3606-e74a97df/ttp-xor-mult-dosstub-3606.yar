rule TTP_XOR_MULT_DOSStub_3606 {
  strings:
    $key_3606 = { 62 6e [2] 16 76 [2] 51 74 [2] 16 65 [2] 58 69 [2] 54 63 [2] 43 68 [2] 58 26 [2] 65 }

  condition:
    any of them
}
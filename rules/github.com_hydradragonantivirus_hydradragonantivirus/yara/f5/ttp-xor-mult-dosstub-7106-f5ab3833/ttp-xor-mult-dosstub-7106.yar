rule TTP_XOR_MULT_DOSStub_7106 {
  strings:
    $key_7106 = { 25 6e [2] 51 76 [2] 16 74 [2] 51 65 [2] 1f 69 [2] 13 63 [2] 04 68 [2] 1f 26 [2] 22 }

  condition:
    any of them
}
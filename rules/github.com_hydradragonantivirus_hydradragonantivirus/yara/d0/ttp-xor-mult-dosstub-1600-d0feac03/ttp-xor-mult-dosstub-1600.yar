rule TTP_XOR_MULT_DOSStub_1600 {
  strings:
    $key_1600 = { 42 68 [2] 36 70 [2] 71 72 [2] 36 63 [2] 78 6f [2] 74 65 [2] 63 6e [2] 78 20 [2] 45 }

  condition:
    any of them
}
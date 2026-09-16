rule TTP_XOR_MULT_DOSStub_4700 {
  strings:
    $key_4700 = { 13 68 [2] 67 70 [2] 20 72 [2] 67 63 [2] 29 6f [2] 25 65 [2] 32 6e [2] 29 20 [2] 14 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3500 {
  strings:
    $key_3500 = { 61 68 [2] 15 70 [2] 52 72 [2] 15 63 [2] 5b 6f [2] 57 65 [2] 40 6e [2] 5b 20 [2] 66 }

  condition:
    any of them
}
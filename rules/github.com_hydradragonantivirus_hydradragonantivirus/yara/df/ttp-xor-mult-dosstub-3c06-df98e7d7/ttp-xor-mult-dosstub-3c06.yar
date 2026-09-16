rule TTP_XOR_MULT_DOSStub_3c06 {
  strings:
    $key_3c06 = { 68 6e [2] 1c 76 [2] 5b 74 [2] 1c 65 [2] 52 69 [2] 5e 63 [2] 49 68 [2] 52 26 [2] 6f }

  condition:
    any of them
}
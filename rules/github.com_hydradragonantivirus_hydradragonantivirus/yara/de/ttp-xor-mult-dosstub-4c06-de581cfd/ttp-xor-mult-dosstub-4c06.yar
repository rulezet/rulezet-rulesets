rule TTP_XOR_MULT_DOSStub_4c06 {
  strings:
    $key_4c06 = { 18 6e [2] 6c 76 [2] 2b 74 [2] 6c 65 [2] 22 69 [2] 2e 63 [2] 39 68 [2] 22 26 [2] 1f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3c00 {
  strings:
    $key_3c00 = { 68 68 [2] 1c 70 [2] 5b 72 [2] 1c 63 [2] 52 6f [2] 5e 65 [2] 49 6e [2] 52 20 [2] 6f }

  condition:
    any of them
}
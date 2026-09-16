rule TTP_XOR_MULT_DOSStub_3c56 {
  strings:
    $key_3c56 = { 68 3e [2] 1c 26 [2] 5b 24 [2] 1c 35 [2] 52 39 [2] 5e 33 [2] 49 38 [2] 52 76 [2] 6f }

  condition:
    any of them
}
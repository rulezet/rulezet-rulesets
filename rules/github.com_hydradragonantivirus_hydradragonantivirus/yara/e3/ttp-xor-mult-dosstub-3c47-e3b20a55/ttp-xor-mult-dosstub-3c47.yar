rule TTP_XOR_MULT_DOSStub_3c47 {
  strings:
    $key_3c47 = { 68 2f [2] 1c 37 [2] 5b 35 [2] 1c 24 [2] 52 28 [2] 5e 22 [2] 49 29 [2] 52 67 [2] 6f }

  condition:
    any of them
}
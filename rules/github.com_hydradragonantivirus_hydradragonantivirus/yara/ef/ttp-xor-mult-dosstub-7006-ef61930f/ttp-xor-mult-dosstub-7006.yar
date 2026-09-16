rule TTP_XOR_MULT_DOSStub_7006 {
  strings:
    $key_7006 = { 24 6e [2] 50 76 [2] 17 74 [2] 50 65 [2] 1e 69 [2] 12 63 [2] 05 68 [2] 1e 26 [2] 23 }

  condition:
    any of them
}
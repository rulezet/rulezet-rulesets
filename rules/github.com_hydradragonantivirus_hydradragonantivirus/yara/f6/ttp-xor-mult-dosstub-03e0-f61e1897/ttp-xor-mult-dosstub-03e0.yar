rule TTP_XOR_MULT_DOSStub_03e0 {
  strings:
    $key_03e0 = { 57 88 [2] 23 90 [2] 64 92 [2] 23 83 [2] 6d 8f [2] 61 85 [2] 76 8e [2] 6d c0 [2] 50 }

  condition:
    any of them
}
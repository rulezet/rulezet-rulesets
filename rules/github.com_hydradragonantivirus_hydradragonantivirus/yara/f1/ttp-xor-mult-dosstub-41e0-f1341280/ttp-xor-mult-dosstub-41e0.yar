rule TTP_XOR_MULT_DOSStub_41e0 {
  strings:
    $key_41e0 = { 15 88 [2] 61 90 [2] 26 92 [2] 61 83 [2] 2f 8f [2] 23 85 [2] 34 8e [2] 2f c0 [2] 12 }

  condition:
    any of them
}
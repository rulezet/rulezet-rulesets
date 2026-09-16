rule TTP_XOR_MULT_DOSStub_78e0 {
  strings:
    $key_78e0 = { 2c 88 [2] 58 90 [2] 1f 92 [2] 58 83 [2] 16 8f [2] 1a 85 [2] 0d 8e [2] 16 c0 [2] 2b }

  condition:
    any of them
}
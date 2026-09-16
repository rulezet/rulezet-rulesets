rule TTP_XOR_MULT_DOSStub_7860 {
  strings:
    $key_7860 = { 2c 08 [2] 58 10 [2] 1f 12 [2] 58 03 [2] 16 0f [2] 1a 05 [2] 0d 0e [2] 16 40 [2] 2b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7867 {
  strings:
    $key_7867 = { 2c 0f [2] 58 17 [2] 1f 15 [2] 58 04 [2] 16 08 [2] 1a 02 [2] 0d 09 [2] 16 47 [2] 2b }

  condition:
    any of them
}
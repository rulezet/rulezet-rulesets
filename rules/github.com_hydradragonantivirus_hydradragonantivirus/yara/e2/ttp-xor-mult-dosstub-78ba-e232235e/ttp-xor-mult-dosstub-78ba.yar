rule TTP_XOR_MULT_DOSStub_78ba {
  strings:
    $key_78ba = { 2c d2 [2] 58 ca [2] 1f c8 [2] 58 d9 [2] 16 d5 [2] 1a df [2] 0d d4 [2] 16 9a [2] 2b }

  condition:
    any of them
}
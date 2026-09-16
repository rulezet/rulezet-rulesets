rule TTP_XOR_MULT_DOSStub_78de {
  strings:
    $key_78de = { 2c b6 [2] 58 ae [2] 1f ac [2] 58 bd [2] 16 b1 [2] 1a bb [2] 0d b0 [2] 16 fe [2] 2b }

  condition:
    any of them
}
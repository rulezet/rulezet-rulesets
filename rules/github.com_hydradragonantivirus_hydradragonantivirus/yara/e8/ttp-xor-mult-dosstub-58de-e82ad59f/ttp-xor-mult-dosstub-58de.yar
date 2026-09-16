rule TTP_XOR_MULT_DOSStub_58de {
  strings:
    $key_58de = { 0c b6 [2] 78 ae [2] 3f ac [2] 78 bd [2] 36 b1 [2] 3a bb [2] 2d b0 [2] 36 fe [2] 0b }

  condition:
    any of them
}
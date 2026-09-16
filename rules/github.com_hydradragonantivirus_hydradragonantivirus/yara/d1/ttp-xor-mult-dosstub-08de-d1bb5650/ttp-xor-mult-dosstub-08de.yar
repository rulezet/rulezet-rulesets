rule TTP_XOR_MULT_DOSStub_08de {
  strings:
    $key_08de = { 5c b6 [2] 28 ae [2] 6f ac [2] 28 bd [2] 66 b1 [2] 6a bb [2] 7d b0 [2] 66 fe [2] 5b }

  condition:
    any of them
}
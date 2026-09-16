rule TTP_XOR_MULT_DOSStub_28de {
  strings:
    $key_28de = { 7c b6 [2] 08 ae [2] 4f ac [2] 08 bd [2] 46 b1 [2] 4a bb [2] 5d b0 [2] 46 fe [2] 7b }

  condition:
    any of them
}
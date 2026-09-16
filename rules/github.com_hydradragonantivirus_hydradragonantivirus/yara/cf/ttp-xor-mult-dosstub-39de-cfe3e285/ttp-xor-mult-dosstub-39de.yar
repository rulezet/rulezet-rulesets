rule TTP_XOR_MULT_DOSStub_39de {
  strings:
    $key_39de = { 6d b6 [2] 19 ae [2] 5e ac [2] 19 bd [2] 57 b1 [2] 5b bb [2] 4c b0 [2] 57 fe [2] 6a }

  condition:
    any of them
}
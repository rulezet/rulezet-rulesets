rule TTP_XOR_MULT_DOSStub_19de {
  strings:
    $key_19de = { 4d b6 [2] 39 ae [2] 7e ac [2] 39 bd [2] 77 b1 [2] 7b bb [2] 6c b0 [2] 77 fe [2] 4a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_69de {
  strings:
    $key_69de = { 3d b6 [2] 49 ae [2] 0e ac [2] 49 bd [2] 07 b1 [2] 0b bb [2] 1c b0 [2] 07 fe [2] 3a }

  condition:
    any of them
}
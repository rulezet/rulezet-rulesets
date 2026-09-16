rule TTP_XOR_MULT_DOSStub_d9de {
  strings:
    $key_d9de = { 8d b6 [2] f9 ae [2] be ac [2] f9 bd [2] b7 b1 [2] bb bb [2] ac b0 [2] b7 fe [2] 8a }

  condition:
    any of them
}
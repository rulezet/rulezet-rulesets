rule TTP_XOR_MULT_DOSStub_dada {
  strings:
    $key_dada = { 8e b2 [2] fa aa [2] bd a8 [2] fa b9 [2] b4 b5 [2] b8 bf [2] af b4 [2] b4 fa [2] 89 }

  condition:
    any of them
}
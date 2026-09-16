rule TTP_XOR_MULT_DOSStub_aada {
  strings:
    $key_aada = { fe b2 [2] 8a aa [2] cd a8 [2] 8a b9 [2] c4 b5 [2] c8 bf [2] df b4 [2] c4 fa [2] f9 }

  condition:
    any of them
}
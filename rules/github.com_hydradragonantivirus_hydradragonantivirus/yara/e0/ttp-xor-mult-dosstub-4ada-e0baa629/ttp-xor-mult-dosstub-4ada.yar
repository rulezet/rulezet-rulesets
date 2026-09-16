rule TTP_XOR_MULT_DOSStub_4ada {
  strings:
    $key_4ada = { 1e b2 [2] 6a aa [2] 2d a8 [2] 6a b9 [2] 24 b5 [2] 28 bf [2] 3f b4 [2] 24 fa [2] 19 }

  condition:
    any of them
}
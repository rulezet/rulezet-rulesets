rule TTP_XOR_MULT_DOSStub_5ada {
  strings:
    $key_5ada = { 0e b2 [2] 7a aa [2] 3d a8 [2] 7a b9 [2] 34 b5 [2] 38 bf [2] 2f b4 [2] 34 fa [2] 09 }

  condition:
    any of them
}
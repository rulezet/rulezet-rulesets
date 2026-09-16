rule TTP_XOR_MULT_DOSStub_6bda {
  strings:
    $key_6bda = { 3f b2 [2] 4b aa [2] 0c a8 [2] 4b b9 [2] 05 b5 [2] 09 bf [2] 1e b4 [2] 05 fa [2] 38 }

  condition:
    any of them
}
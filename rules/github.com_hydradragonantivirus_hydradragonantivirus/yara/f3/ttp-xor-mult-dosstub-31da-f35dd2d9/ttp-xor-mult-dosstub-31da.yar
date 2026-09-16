rule TTP_XOR_MULT_DOSStub_31da {
  strings:
    $key_31da = { 65 b2 [2] 11 aa [2] 56 a8 [2] 11 b9 [2] 5f b5 [2] 53 bf [2] 44 b4 [2] 5f fa [2] 62 }

  condition:
    any of them
}
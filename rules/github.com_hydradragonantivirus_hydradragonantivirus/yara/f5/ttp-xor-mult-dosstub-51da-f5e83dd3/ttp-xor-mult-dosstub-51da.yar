rule TTP_XOR_MULT_DOSStub_51da {
  strings:
    $key_51da = { 05 b2 [2] 71 aa [2] 36 a8 [2] 71 b9 [2] 3f b5 [2] 33 bf [2] 24 b4 [2] 3f fa [2] 02 }

  condition:
    any of them
}
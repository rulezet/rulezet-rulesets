rule TTP_XOR_MULT_DOSStub_22da {
  strings:
    $key_22da = { 76 b2 [2] 02 aa [2] 45 a8 [2] 02 b9 [2] 4c b5 [2] 40 bf [2] 57 b4 [2] 4c fa [2] 71 }

  condition:
    any of them
}
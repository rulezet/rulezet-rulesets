rule TTP_XOR_MULT_DOSStub_39dc {
  strings:
    $key_39dc = { 6d b4 [2] 19 ac [2] 5e ae [2] 19 bf [2] 57 b3 [2] 5b b9 [2] 4c b2 [2] 57 fc [2] 6a }

  condition:
    any of them
}
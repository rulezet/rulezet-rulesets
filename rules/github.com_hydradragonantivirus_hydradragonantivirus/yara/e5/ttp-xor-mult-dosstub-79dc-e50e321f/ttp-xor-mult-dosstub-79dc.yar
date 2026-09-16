rule TTP_XOR_MULT_DOSStub_79dc {
  strings:
    $key_79dc = { 2d b4 [2] 59 ac [2] 1e ae [2] 59 bf [2] 17 b3 [2] 1b b9 [2] 0c b2 [2] 17 fc [2] 2a }

  condition:
    any of them
}
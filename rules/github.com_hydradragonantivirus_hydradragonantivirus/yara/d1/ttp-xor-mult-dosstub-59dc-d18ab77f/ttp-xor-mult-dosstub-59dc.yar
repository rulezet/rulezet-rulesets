rule TTP_XOR_MULT_DOSStub_59dc {
  strings:
    $key_59dc = { 0d b4 [2] 79 ac [2] 3e ae [2] 79 bf [2] 37 b3 [2] 3b b9 [2] 2c b2 [2] 37 fc [2] 0a }

  condition:
    any of them
}
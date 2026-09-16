rule TTP_XOR_MULT_DOSStub_19dc {
  strings:
    $key_19dc = { 4d b4 [2] 39 ac [2] 7e ae [2] 39 bf [2] 77 b3 [2] 7b b9 [2] 6c b2 [2] 77 fc [2] 4a }

  condition:
    any of them
}
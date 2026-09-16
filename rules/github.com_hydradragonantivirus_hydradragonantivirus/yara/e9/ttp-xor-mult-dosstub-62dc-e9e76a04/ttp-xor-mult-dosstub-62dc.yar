rule TTP_XOR_MULT_DOSStub_62dc {
  strings:
    $key_62dc = { 36 b4 [2] 42 ac [2] 05 ae [2] 42 bf [2] 0c b3 [2] 00 b9 [2] 17 b2 [2] 0c fc [2] 31 }

  condition:
    any of them
}
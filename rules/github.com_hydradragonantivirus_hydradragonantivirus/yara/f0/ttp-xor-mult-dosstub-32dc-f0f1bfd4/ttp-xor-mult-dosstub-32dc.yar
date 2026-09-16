rule TTP_XOR_MULT_DOSStub_32dc {
  strings:
    $key_32dc = { 66 b4 [2] 12 ac [2] 55 ae [2] 12 bf [2] 5c b3 [2] 50 b9 [2] 47 b2 [2] 5c fc [2] 61 }

  condition:
    any of them
}
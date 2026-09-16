rule TTP_XOR_MULT_DOSStub_12dc {
  strings:
    $key_12dc = { 46 b4 [2] 32 ac [2] 75 ae [2] 32 bf [2] 7c b3 [2] 70 b9 [2] 67 b2 [2] 7c fc [2] 41 }

  condition:
    any of them
}
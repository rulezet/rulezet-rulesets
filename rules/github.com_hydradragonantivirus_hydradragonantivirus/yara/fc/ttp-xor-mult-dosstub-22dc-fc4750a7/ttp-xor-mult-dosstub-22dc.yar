rule TTP_XOR_MULT_DOSStub_22dc {
  strings:
    $key_22dc = { 76 b4 [2] 02 ac [2] 45 ae [2] 02 bf [2] 4c b3 [2] 40 b9 [2] 57 b2 [2] 4c fc [2] 71 }

  condition:
    any of them
}
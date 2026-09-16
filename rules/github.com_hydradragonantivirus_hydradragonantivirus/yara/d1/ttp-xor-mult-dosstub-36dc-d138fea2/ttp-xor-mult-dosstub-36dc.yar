rule TTP_XOR_MULT_DOSStub_36dc {
  strings:
    $key_36dc = { 62 b4 [2] 16 ac [2] 51 ae [2] 16 bf [2] 58 b3 [2] 54 b9 [2] 43 b2 [2] 58 fc [2] 65 }

  condition:
    any of them
}
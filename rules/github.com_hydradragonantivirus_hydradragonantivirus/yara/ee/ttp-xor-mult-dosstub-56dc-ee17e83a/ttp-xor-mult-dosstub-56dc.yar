rule TTP_XOR_MULT_DOSStub_56dc {
  strings:
    $key_56dc = { 02 b4 [2] 76 ac [2] 31 ae [2] 76 bf [2] 38 b3 [2] 34 b9 [2] 23 b2 [2] 38 fc [2] 05 }

  condition:
    any of them
}
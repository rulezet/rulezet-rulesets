rule TTP_XOR_MULT_DOSStub_44dc {
  strings:
    $key_44dc = { 10 b4 [2] 64 ac [2] 23 ae [2] 64 bf [2] 2a b3 [2] 26 b9 [2] 31 b2 [2] 2a fc [2] 17 }

  condition:
    any of them
}
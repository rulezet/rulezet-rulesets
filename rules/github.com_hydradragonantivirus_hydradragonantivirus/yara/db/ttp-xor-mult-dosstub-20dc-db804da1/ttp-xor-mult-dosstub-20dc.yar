rule TTP_XOR_MULT_DOSStub_20dc {
  strings:
    $key_20dc = { 74 b4 [2] 00 ac [2] 47 ae [2] 00 bf [2] 4e b3 [2] 42 b9 [2] 55 b2 [2] 4e fc [2] 73 }

  condition:
    any of them
}
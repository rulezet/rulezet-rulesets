rule TTP_XOR_MULT_DOSStub_e7dc {
  strings:
    $key_e7dc = { b3 b4 [2] c7 ac [2] 80 ae [2] c7 bf [2] 89 b3 [2] 85 b9 [2] 92 b2 [2] 89 fc [2] b4 }

  condition:
    any of them
}
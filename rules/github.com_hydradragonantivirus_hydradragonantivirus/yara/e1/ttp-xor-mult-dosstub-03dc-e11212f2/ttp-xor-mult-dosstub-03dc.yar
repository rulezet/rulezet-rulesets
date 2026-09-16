rule TTP_XOR_MULT_DOSStub_03dc {
  strings:
    $key_03dc = { 57 b4 [2] 23 ac [2] 64 ae [2] 23 bf [2] 6d b3 [2] 61 b9 [2] 76 b2 [2] 6d fc [2] 50 }

  condition:
    any of them
}
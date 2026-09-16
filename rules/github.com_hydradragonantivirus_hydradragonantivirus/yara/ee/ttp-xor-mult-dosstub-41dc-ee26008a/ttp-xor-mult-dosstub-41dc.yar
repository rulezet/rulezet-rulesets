rule TTP_XOR_MULT_DOSStub_41dc {
  strings:
    $key_41dc = { 15 b4 [2] 61 ac [2] 26 ae [2] 61 bf [2] 2f b3 [2] 23 b9 [2] 34 b2 [2] 2f fc [2] 12 }

  condition:
    any of them
}
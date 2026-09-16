rule TTP_XOR_MULT_DOSStub_e5dc {
  strings:
    $key_e5dc = { b1 b4 [2] c5 ac [2] 82 ae [2] c5 bf [2] 8b b3 [2] 87 b9 [2] 90 b2 [2] 8b fc [2] b6 }

  condition:
    any of them
}
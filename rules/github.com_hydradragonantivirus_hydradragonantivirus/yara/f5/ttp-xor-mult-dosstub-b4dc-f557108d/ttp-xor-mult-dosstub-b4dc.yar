rule TTP_XOR_MULT_DOSStub_b4dc {
  strings:
    $key_b4dc = { e0 b4 [2] 94 ac [2] d3 ae [2] 94 bf [2] da b3 [2] d6 b9 [2] c1 b2 [2] da fc [2] e7 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b1dc {
  strings:
    $key_b1dc = { e5 b4 [2] 91 ac [2] d6 ae [2] 91 bf [2] df b3 [2] d3 b9 [2] c4 b2 [2] df fc [2] e2 }

  condition:
    any of them
}
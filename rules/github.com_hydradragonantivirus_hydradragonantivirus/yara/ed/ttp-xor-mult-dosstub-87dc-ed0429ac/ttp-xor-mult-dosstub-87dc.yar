rule TTP_XOR_MULT_DOSStub_87dc {
  strings:
    $key_87dc = { d3 b4 [2] a7 ac [2] e0 ae [2] a7 bf [2] e9 b3 [2] e5 b9 [2] f2 b2 [2] e9 fc [2] d4 }

  condition:
    any of them
}
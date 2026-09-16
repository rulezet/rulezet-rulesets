rule TTP_XOR_MULT_DOSStub_f3dc {
  strings:
    $key_f3dc = { a7 b4 [2] d3 ac [2] 94 ae [2] d3 bf [2] 9d b3 [2] 91 b9 [2] 86 b2 [2] 9d fc [2] a0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f3da {
  strings:
    $key_f3da = { a7 b2 [2] d3 aa [2] 94 a8 [2] d3 b9 [2] 9d b5 [2] 91 bf [2] 86 b4 [2] 9d fa [2] a0 }

  condition:
    any of them
}
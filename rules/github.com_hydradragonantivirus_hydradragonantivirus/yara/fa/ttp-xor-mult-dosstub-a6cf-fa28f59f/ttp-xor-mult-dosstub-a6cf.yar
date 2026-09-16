rule TTP_XOR_MULT_DOSStub_a6cf {
  strings:
    $key_a6cf = { f2 a7 [2] 86 bf [2] c1 bd [2] 86 ac [2] c8 a0 [2] c4 aa [2] d3 a1 [2] c8 ef [2] f5 }

  condition:
    any of them
}
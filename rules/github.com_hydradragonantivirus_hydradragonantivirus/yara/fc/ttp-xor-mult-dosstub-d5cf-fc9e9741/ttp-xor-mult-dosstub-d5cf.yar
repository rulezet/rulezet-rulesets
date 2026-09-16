rule TTP_XOR_MULT_DOSStub_d5cf {
  strings:
    $key_d5cf = { 81 a7 [2] f5 bf [2] b2 bd [2] f5 ac [2] bb a0 [2] b7 aa [2] a0 a1 [2] bb ef [2] 86 }

  condition:
    any of them
}
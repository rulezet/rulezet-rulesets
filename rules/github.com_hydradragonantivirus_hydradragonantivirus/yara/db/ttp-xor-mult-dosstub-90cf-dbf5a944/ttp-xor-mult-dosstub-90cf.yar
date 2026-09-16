rule TTP_XOR_MULT_DOSStub_90cf {
  strings:
    $key_90cf = { c4 a7 [2] b0 bf [2] f7 bd [2] b0 ac [2] fe a0 [2] f2 aa [2] e5 a1 [2] fe ef [2] c3 }

  condition:
    any of them
}
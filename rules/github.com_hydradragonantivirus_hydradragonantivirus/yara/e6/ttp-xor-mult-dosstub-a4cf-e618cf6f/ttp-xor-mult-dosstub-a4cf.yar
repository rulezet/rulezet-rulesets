rule TTP_XOR_MULT_DOSStub_a4cf {
  strings:
    $key_a4cf = { f0 a7 [2] 84 bf [2] c3 bd [2] 84 ac [2] ca a0 [2] c6 aa [2] d1 a1 [2] ca ef [2] f7 }

  condition:
    any of them
}
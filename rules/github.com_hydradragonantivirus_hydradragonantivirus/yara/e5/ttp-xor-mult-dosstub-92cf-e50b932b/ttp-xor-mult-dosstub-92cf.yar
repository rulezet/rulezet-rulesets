rule TTP_XOR_MULT_DOSStub_92cf {
  strings:
    $key_92cf = { c6 a7 [2] b2 bf [2] f5 bd [2] b2 ac [2] fc a0 [2] f0 aa [2] e7 a1 [2] fc ef [2] c1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_87cf {
  strings:
    $key_87cf = { d3 a7 [2] a7 bf [2] e0 bd [2] a7 ac [2] e9 a0 [2] e5 aa [2] f2 a1 [2] e9 ef [2] d4 }

  condition:
    any of them
}
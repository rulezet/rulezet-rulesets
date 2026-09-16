rule TTP_XOR_MULT_DOSStub_c3cf {
  strings:
    $key_c3cf = { 97 a7 [2] e3 bf [2] a4 bd [2] e3 ac [2] ad a0 [2] a1 aa [2] b6 a1 [2] ad ef [2] 90 }

  condition:
    any of them
}
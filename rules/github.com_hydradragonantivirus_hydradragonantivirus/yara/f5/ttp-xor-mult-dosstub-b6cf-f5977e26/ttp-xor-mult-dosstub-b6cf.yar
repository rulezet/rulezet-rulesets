rule TTP_XOR_MULT_DOSStub_b6cf {
  strings:
    $key_b6cf = { e2 a7 [2] 96 bf [2] d1 bd [2] 96 ac [2] d8 a0 [2] d4 aa [2] c3 a1 [2] d8 ef [2] e5 }

  condition:
    any of them
}
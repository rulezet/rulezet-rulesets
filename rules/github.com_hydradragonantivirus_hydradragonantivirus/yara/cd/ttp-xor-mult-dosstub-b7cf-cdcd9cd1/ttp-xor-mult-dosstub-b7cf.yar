rule TTP_XOR_MULT_DOSStub_b7cf {
  strings:
    $key_b7cf = { e3 a7 [2] 97 bf [2] d0 bd [2] 97 ac [2] d9 a0 [2] d5 aa [2] c2 a1 [2] d9 ef [2] e4 }

  condition:
    any of them
}
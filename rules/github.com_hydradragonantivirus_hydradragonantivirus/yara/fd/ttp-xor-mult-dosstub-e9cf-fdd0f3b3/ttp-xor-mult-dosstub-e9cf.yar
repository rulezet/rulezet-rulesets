rule TTP_XOR_MULT_DOSStub_e9cf {
  strings:
    $key_e9cf = { bd a7 [2] c9 bf [2] 8e bd [2] c9 ac [2] 87 a0 [2] 8b aa [2] 9c a1 [2] 87 ef [2] ba }

  condition:
    any of them
}
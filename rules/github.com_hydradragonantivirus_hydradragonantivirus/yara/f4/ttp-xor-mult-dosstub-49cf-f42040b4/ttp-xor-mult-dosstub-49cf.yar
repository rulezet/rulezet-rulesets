rule TTP_XOR_MULT_DOSStub_49cf {
  strings:
    $key_49cf = { 1d a7 [2] 69 bf [2] 2e bd [2] 69 ac [2] 27 a0 [2] 2b aa [2] 3c a1 [2] 27 ef [2] 1a }

  condition:
    any of them
}
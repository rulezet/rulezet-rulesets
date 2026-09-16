rule TTP_XOR_MULT_DOSStub_79cf {
  strings:
    $key_79cf = { 2d a7 [2] 59 bf [2] 1e bd [2] 59 ac [2] 17 a0 [2] 1b aa [2] 0c a1 [2] 17 ef [2] 2a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_69cf {
  strings:
    $key_69cf = { 3d a7 [2] 49 bf [2] 0e bd [2] 49 ac [2] 07 a0 [2] 0b aa [2] 1c a1 [2] 07 ef [2] 3a }

  condition:
    any of them
}
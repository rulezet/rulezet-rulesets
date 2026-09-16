rule TTP_XOR_MULT_DOSStub_42cf {
  strings:
    $key_42cf = { 16 a7 [2] 62 bf [2] 25 bd [2] 62 ac [2] 2c a0 [2] 20 aa [2] 37 a1 [2] 2c ef [2] 11 }

  condition:
    any of them
}
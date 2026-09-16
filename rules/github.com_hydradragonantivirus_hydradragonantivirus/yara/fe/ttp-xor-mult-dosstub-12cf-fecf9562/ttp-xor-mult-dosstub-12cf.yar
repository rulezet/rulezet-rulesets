rule TTP_XOR_MULT_DOSStub_12cf {
  strings:
    $key_12cf = { 46 a7 [2] 32 bf [2] 75 bd [2] 32 ac [2] 7c a0 [2] 70 aa [2] 67 a1 [2] 7c ef [2] 41 }

  condition:
    any of them
}
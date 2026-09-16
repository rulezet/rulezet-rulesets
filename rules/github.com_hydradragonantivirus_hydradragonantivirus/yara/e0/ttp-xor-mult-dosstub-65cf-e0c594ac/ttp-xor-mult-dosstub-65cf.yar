rule TTP_XOR_MULT_DOSStub_65cf {
  strings:
    $key_65cf = { 31 a7 [2] 45 bf [2] 02 bd [2] 45 ac [2] 0b a0 [2] 07 aa [2] 10 a1 [2] 0b ef [2] 36 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_24cf {
  strings:
    $key_24cf = { 70 a7 [2] 04 bf [2] 43 bd [2] 04 ac [2] 4a a0 [2] 46 aa [2] 51 a1 [2] 4a ef [2] 77 }

  condition:
    any of them
}
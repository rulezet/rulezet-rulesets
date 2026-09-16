rule TTP_XOR_MULT_DOSStub_50cf {
  strings:
    $key_50cf = { 04 a7 [2] 70 bf [2] 37 bd [2] 70 ac [2] 3e a0 [2] 32 aa [2] 25 a1 [2] 3e ef [2] 03 }

  condition:
    any of them
}
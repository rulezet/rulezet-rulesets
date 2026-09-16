rule TTP_XOR_MULT_DOSStub_25cf {
  strings:
    $key_25cf = { 71 a7 [2] 05 bf [2] 42 bd [2] 05 ac [2] 4b a0 [2] 47 aa [2] 50 a1 [2] 4b ef [2] 76 }

  condition:
    any of them
}
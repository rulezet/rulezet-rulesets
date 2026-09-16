rule TTP_XOR_MULT_DOSStub_30cf {
  strings:
    $key_30cf = { 64 a7 [2] 10 bf [2] 57 bd [2] 10 ac [2] 5e a0 [2] 52 aa [2] 45 a1 [2] 5e ef [2] 63 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_22cf {
  strings:
    $key_22cf = { 76 a7 [2] 02 bf [2] 45 bd [2] 02 ac [2] 4c a0 [2] 40 aa [2] 57 a1 [2] 4c ef [2] 71 }

  condition:
    any of them
}
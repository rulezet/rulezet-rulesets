rule TTP_XOR_MULT_DOSStub_02cf {
  strings:
    $key_02cf = { 56 a7 [2] 22 bf [2] 65 bd [2] 22 ac [2] 6c a0 [2] 60 aa [2] 77 a1 [2] 6c ef [2] 51 }

  condition:
    any of them
}
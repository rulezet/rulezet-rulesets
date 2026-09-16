rule TTP_XOR_MULT_DOSStub_f5cf {
  strings:
    $key_f5cf = { a1 a7 [2] d5 bf [2] 92 bd [2] d5 ac [2] 9b a0 [2] 97 aa [2] 80 a1 [2] 9b ef [2] a6 }

  condition:
    any of them
}
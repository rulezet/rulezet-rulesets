rule TTP_XOR_MULT_DOSStub_e0cf {
  strings:
    $key_e0cf = { b4 a7 [2] c0 bf [2] 87 bd [2] c0 ac [2] 8e a0 [2] 82 aa [2] 95 a1 [2] 8e ef [2] b3 }

  condition:
    any of them
}
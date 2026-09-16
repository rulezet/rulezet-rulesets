rule TTP_XOR_MULT_DOSStub_a5cf {
  strings:
    $key_a5cf = { f1 a7 [2] 85 bf [2] c2 bd [2] 85 ac [2] cb a0 [2] c7 aa [2] d0 a1 [2] cb ef [2] f6 }

  condition:
    any of them
}
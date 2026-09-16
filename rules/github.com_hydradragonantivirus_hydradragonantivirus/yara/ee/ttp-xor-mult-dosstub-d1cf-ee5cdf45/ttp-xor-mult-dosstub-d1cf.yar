rule TTP_XOR_MULT_DOSStub_d1cf {
  strings:
    $key_d1cf = { 85 a7 [2] f1 bf [2] b6 bd [2] f1 ac [2] bf a0 [2] b3 aa [2] a4 a1 [2] bf ef [2] 82 }

  condition:
    any of them
}
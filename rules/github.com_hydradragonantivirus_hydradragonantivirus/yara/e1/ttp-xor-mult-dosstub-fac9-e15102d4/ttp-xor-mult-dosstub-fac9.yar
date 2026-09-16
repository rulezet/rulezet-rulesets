rule TTP_XOR_MULT_DOSStub_fac9 {
  strings:
    $key_fac9 = { ae a1 [2] da b9 [2] 9d bb [2] da aa [2] 94 a6 [2] 98 ac [2] 8f a7 [2] 94 e9 [2] a9 }

  condition:
    any of them
}
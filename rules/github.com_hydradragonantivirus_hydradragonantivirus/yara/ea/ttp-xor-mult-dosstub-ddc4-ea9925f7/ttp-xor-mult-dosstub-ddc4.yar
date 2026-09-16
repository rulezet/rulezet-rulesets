rule TTP_XOR_MULT_DOSStub_ddc4 {
  strings:
    $key_ddc4 = { 89 ac [2] fd b4 [2] ba b6 [2] fd a7 [2] b3 ab [2] bf a1 [2] a8 aa [2] b3 e4 [2] 8e }

  condition:
    any of them
}
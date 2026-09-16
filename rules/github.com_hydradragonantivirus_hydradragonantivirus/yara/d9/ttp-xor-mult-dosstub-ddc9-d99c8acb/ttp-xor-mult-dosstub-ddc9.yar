rule TTP_XOR_MULT_DOSStub_ddc9 {
  strings:
    $key_ddc9 = { 89 a1 [2] fd b9 [2] ba bb [2] fd aa [2] b3 a6 [2] bf ac [2] a8 a7 [2] b3 e9 [2] 8e }

  condition:
    any of them
}
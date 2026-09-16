rule TTP_XOR_MULT_DOSStub_bfc9 {
  strings:
    $key_bfc9 = { eb a1 [2] 9f b9 [2] d8 bb [2] 9f aa [2] d1 a6 [2] dd ac [2] ca a7 [2] d1 e9 [2] ec }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bac2 {
  strings:
    $key_bac2 = { ee aa [2] 9a b2 [2] dd b0 [2] 9a a1 [2] d4 ad [2] d8 a7 [2] cf ac [2] d4 e2 [2] e9 }

  condition:
    any of them
}
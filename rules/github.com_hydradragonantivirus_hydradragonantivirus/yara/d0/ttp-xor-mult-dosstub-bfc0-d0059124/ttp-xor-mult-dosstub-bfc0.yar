rule TTP_XOR_MULT_DOSStub_bfc0 {
  strings:
    $key_bfc0 = { eb a8 [2] 9f b0 [2] d8 b2 [2] 9f a3 [2] d1 af [2] dd a5 [2] ca ae [2] d1 e0 [2] ec }

  condition:
    any of them
}
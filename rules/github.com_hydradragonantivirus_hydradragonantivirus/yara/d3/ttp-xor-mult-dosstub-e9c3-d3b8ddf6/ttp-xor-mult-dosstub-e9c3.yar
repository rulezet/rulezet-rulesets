rule TTP_XOR_MULT_DOSStub_e9c3 {
  strings:
    $key_e9c3 = { bd ab [2] c9 b3 [2] 8e b1 [2] c9 a0 [2] 87 ac [2] 8b a6 [2] 9c ad [2] 87 e3 [2] ba }

  condition:
    any of them
}
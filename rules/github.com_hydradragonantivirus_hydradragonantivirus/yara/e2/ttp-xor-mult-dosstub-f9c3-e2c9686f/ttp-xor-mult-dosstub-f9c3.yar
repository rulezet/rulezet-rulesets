rule TTP_XOR_MULT_DOSStub_f9c3 {
  strings:
    $key_f9c3 = { ad ab [2] d9 b3 [2] 9e b1 [2] d9 a0 [2] 97 ac [2] 9b a6 [2] 8c ad [2] 97 e3 [2] aa }

  condition:
    any of them
}
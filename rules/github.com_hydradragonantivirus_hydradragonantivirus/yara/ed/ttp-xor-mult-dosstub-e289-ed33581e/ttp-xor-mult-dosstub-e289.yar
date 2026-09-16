rule TTP_XOR_MULT_DOSStub_e289 {
  strings:
    $key_e289 = { b6 e1 [2] c2 f9 [2] 85 fb [2] c2 ea [2] 8c e6 [2] 80 ec [2] 97 e7 [2] 8c a9 [2] b1 }

  condition:
    any of them
}
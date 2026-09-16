rule TTP_XOR_MULT_DOSStub_e28d {
  strings:
    $key_e28d = { b6 e5 [2] c2 fd [2] 85 ff [2] c2 ee [2] 8c e2 [2] 80 e8 [2] 97 e3 [2] 8c ad [2] b1 }

  condition:
    any of them
}
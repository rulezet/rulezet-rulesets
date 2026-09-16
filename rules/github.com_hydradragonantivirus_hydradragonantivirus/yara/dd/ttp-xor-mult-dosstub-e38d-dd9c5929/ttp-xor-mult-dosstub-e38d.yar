rule TTP_XOR_MULT_DOSStub_e38d {
  strings:
    $key_e38d = { b7 e5 [2] c3 fd [2] 84 ff [2] c3 ee [2] 8d e2 [2] 81 e8 [2] 96 e3 [2] 8d ad [2] b0 }

  condition:
    any of them
}
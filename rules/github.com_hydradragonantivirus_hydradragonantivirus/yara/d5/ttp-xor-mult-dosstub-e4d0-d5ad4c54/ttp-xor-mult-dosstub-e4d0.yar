rule TTP_XOR_MULT_DOSStub_e4d0 {
  strings:
    $key_e4d0 = { b0 b8 [2] c4 a0 [2] 83 a2 [2] c4 b3 [2] 8a bf [2] 86 b5 [2] 91 be [2] 8a f0 [2] b7 }

  condition:
    any of them
}
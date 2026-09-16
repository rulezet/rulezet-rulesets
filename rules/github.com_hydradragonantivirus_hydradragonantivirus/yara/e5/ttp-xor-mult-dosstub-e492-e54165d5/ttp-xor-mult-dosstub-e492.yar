rule TTP_XOR_MULT_DOSStub_e492 {
  strings:
    $key_e492 = { b0 fa [2] c4 e2 [2] 83 e0 [2] c4 f1 [2] 8a fd [2] 86 f7 [2] 91 fc [2] 8a b2 [2] b7 }

  condition:
    any of them
}
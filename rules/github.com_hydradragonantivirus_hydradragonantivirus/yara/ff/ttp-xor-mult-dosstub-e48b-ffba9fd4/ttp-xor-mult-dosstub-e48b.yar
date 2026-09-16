rule TTP_XOR_MULT_DOSStub_e48b {
  strings:
    $key_e48b = { b0 e3 [2] c4 fb [2] 83 f9 [2] c4 e8 [2] 8a e4 [2] 86 ee [2] 91 e5 [2] 8a ab [2] b7 }

  condition:
    any of them
}
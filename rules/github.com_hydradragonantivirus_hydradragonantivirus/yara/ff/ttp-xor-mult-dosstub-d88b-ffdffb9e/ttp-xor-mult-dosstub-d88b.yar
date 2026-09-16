rule TTP_XOR_MULT_DOSStub_d88b {
  strings:
    $key_d88b = { 8c e3 [2] f8 fb [2] bf f9 [2] f8 e8 [2] b6 e4 [2] ba ee [2] ad e5 [2] b6 ab [2] 8b }

  condition:
    any of them
}
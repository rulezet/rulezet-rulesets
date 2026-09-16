rule TTP_XOR_MULT_DOSStub_44ce {
  strings:
    $key_44ce = { 10 a6 [2] 64 be [2] 23 bc [2] 64 ad [2] 2a a1 [2] 26 ab [2] 31 a0 [2] 2a ee [2] 17 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_25ce {
  strings:
    $key_25ce = { 71 a6 [2] 05 be [2] 42 bc [2] 05 ad [2] 4b a1 [2] 47 ab [2] 50 a0 [2] 4b ee [2] 76 }

  condition:
    any of them
}
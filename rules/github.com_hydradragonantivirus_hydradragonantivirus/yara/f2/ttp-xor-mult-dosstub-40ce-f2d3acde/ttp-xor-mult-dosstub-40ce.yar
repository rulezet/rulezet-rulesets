rule TTP_XOR_MULT_DOSStub_40ce {
  strings:
    $key_40ce = { 14 a6 [2] 60 be [2] 27 bc [2] 60 ad [2] 2e a1 [2] 22 ab [2] 35 a0 [2] 2e ee [2] 13 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_10ce {
  strings:
    $key_10ce = { 44 a6 [2] 30 be [2] 77 bc [2] 30 ad [2] 7e a1 [2] 72 ab [2] 65 a0 [2] 7e ee [2] 43 }

  condition:
    any of them
}
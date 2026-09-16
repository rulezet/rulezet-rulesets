rule TTP_XOR_MULT_DOSStub_57ce {
  strings:
    $key_57ce = { 03 a6 [2] 77 be [2] 30 bc [2] 77 ad [2] 39 a1 [2] 35 ab [2] 22 a0 [2] 39 ee [2] 04 }

  condition:
    any of them
}
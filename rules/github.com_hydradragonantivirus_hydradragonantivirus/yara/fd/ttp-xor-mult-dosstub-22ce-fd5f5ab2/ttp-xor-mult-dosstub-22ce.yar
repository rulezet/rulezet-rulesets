rule TTP_XOR_MULT_DOSStub_22ce {
  strings:
    $key_22ce = { 76 a6 [2] 02 be [2] 45 bc [2] 02 ad [2] 4c a1 [2] 40 ab [2] 57 a0 [2] 4c ee [2] 71 }

  condition:
    any of them
}
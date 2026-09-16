rule TTP_XOR_MULT_DOSStub_32ce {
  strings:
    $key_32ce = { 66 a6 [2] 12 be [2] 55 bc [2] 12 ad [2] 5c a1 [2] 50 ab [2] 47 a0 [2] 5c ee [2] 61 }

  condition:
    any of them
}
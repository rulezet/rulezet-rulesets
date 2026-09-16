rule TTP_XOR_MULT_DOSStub_37ce {
  strings:
    $key_37ce = { 63 a6 [2] 17 be [2] 50 bc [2] 17 ad [2] 59 a1 [2] 55 ab [2] 42 a0 [2] 59 ee [2] 64 }

  condition:
    any of them
}
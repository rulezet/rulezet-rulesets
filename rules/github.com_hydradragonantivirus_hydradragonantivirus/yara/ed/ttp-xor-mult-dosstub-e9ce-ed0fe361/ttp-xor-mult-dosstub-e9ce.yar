rule TTP_XOR_MULT_DOSStub_e9ce {
  strings:
    $key_e9ce = { bd a6 [2] c9 be [2] 8e bc [2] c9 ad [2] 87 a1 [2] 8b ab [2] 9c a0 [2] 87 ee [2] ba }

  condition:
    any of them
}
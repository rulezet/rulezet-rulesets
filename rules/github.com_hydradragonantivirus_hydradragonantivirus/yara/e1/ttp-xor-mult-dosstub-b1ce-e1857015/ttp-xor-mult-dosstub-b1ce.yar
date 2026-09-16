rule TTP_XOR_MULT_DOSStub_b1ce {
  strings:
    $key_b1ce = { e5 a6 [2] 91 be [2] d6 bc [2] 91 ad [2] df a1 [2] d3 ab [2] c4 a0 [2] df ee [2] e2 }

  condition:
    any of them
}
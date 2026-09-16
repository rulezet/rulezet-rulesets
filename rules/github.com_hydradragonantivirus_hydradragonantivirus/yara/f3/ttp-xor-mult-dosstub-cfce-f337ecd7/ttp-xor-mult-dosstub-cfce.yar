rule TTP_XOR_MULT_DOSStub_cfce {
  strings:
    $key_cfce = { 9b a6 [2] ef be [2] a8 bc [2] ef ad [2] a1 a1 [2] ad ab [2] ba a0 [2] a1 ee [2] 9c }

  condition:
    any of them
}
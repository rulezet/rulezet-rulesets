rule TTP_XOR_MULT_DOSStub_b195 {
  strings:
    $key_b195 = { e5 fd [2] 91 e5 [2] d6 e7 [2] 91 f6 [2] df fa [2] d3 f0 [2] c4 fb [2] df b5 [2] e2 }

  condition:
    any of them
}
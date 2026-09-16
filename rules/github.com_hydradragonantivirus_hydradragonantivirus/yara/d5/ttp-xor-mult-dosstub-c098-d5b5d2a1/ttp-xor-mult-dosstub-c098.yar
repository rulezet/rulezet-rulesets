rule TTP_XOR_MULT_DOSStub_c098 {
  strings:
    $key_c098 = { 94 f0 [2] e0 e8 [2] a7 ea [2] e0 fb [2] ae f7 [2] a2 fd [2] b5 f6 [2] ae b8 [2] 93 }

  condition:
    any of them
}
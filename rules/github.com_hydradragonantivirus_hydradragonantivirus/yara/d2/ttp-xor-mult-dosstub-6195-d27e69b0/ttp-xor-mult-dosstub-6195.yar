rule TTP_XOR_MULT_DOSStub_6195 {
  strings:
    $key_6195 = { 35 fd [2] 41 e5 [2] 06 e7 [2] 41 f6 [2] 0f fa [2] 03 f0 [2] 14 fb [2] 0f b5 [2] 32 }

  condition:
    any of them
}
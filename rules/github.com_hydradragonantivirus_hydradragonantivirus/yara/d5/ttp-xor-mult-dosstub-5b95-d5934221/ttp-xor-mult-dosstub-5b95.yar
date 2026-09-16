rule TTP_XOR_MULT_DOSStub_5b95 {
  strings:
    $key_5b95 = { 0f fd [2] 7b e5 [2] 3c e7 [2] 7b f6 [2] 35 fa [2] 39 f0 [2] 2e fb [2] 35 b5 [2] 08 }

  condition:
    any of them
}
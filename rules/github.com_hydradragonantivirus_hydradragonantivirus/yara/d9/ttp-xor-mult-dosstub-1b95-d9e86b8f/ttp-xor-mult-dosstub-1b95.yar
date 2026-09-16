rule TTP_XOR_MULT_DOSStub_1b95 {
  strings:
    $key_1b95 = { 4f fd [2] 3b e5 [2] 7c e7 [2] 3b f6 [2] 75 fa [2] 79 f0 [2] 6e fb [2] 75 b5 [2] 48 }

  condition:
    any of them
}
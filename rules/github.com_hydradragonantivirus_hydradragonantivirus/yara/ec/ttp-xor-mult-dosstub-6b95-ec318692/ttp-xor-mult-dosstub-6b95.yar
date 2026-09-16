rule TTP_XOR_MULT_DOSStub_6b95 {
  strings:
    $key_6b95 = { 3f fd [2] 4b e5 [2] 0c e7 [2] 4b f6 [2] 05 fa [2] 09 f0 [2] 1e fb [2] 05 b5 [2] 38 }

  condition:
    any of them
}
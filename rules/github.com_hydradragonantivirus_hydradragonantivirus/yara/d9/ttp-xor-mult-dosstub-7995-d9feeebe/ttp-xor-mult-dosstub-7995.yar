rule TTP_XOR_MULT_DOSStub_7995 {
  strings:
    $key_7995 = { 2d fd [2] 59 e5 [2] 1e e7 [2] 59 f6 [2] 17 fa [2] 1b f0 [2] 0c fb [2] 17 b5 [2] 2a }

  condition:
    any of them
}
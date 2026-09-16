rule TTP_XOR_MULT_DOSStub_0995 {
  strings:
    $key_0995 = { 5d fd [2] 29 e5 [2] 6e e7 [2] 29 f6 [2] 67 fa [2] 6b f0 [2] 7c fb [2] 67 b5 [2] 5a }

  condition:
    any of them
}
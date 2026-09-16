rule TTP_XOR_MULT_DOSStub_e995 {
  strings:
    $key_e995 = { bd fd [2] c9 e5 [2] 8e e7 [2] c9 f6 [2] 87 fa [2] 8b f0 [2] 9c fb [2] 87 b5 [2] ba }

  condition:
    any of them
}
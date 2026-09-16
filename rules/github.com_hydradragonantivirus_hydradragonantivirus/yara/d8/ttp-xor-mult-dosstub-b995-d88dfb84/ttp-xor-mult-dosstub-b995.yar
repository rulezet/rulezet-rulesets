rule TTP_XOR_MULT_DOSStub_b995 {
  strings:
    $key_b995 = { ed fd [2] 99 e5 [2] de e7 [2] 99 f6 [2] d7 fa [2] db f0 [2] cc fb [2] d7 b5 [2] ea }

  condition:
    any of them
}
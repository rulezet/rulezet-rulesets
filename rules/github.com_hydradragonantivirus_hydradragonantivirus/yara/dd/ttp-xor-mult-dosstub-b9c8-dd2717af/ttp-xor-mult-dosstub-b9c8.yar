rule TTP_XOR_MULT_DOSStub_b9c8 {
  strings:
    $key_b9c8 = { ed a0 [2] 99 b8 [2] de ba [2] 99 ab [2] d7 a7 [2] db ad [2] cc a6 [2] d7 e8 [2] ea }

  condition:
    any of them
}
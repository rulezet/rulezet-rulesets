rule TTP_XOR_MULT_DOSStub_aeb3 {
  strings:
    $key_aeb3 = { fa db [2] 8e c3 [2] c9 c1 [2] 8e d0 [2] c0 dc [2] cc d6 [2] db dd [2] c0 93 [2] fd }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_afc8 {
  strings:
    $key_afc8 = { fb a0 [2] 8f b8 [2] c8 ba [2] 8f ab [2] c1 a7 [2] cd ad [2] da a6 [2] c1 e8 [2] fc }

  condition:
    any of them
}
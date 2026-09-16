rule TTP_XOR_MULT_DOSStub_bed1 {
  strings:
    $key_bed1 = { ea b9 [2] 9e a1 [2] d9 a3 [2] 9e b2 [2] d0 be [2] dc b4 [2] cb bf [2] d0 f1 [2] ed }

  condition:
    any of them
}
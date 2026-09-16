rule TTP_XOR_MULT_DOSStub_bec2 {
  strings:
    $key_bec2 = { ea aa [2] 9e b2 [2] d9 b0 [2] 9e a1 [2] d0 ad [2] dc a7 [2] cb ac [2] d0 e2 [2] ed }

  condition:
    any of them
}
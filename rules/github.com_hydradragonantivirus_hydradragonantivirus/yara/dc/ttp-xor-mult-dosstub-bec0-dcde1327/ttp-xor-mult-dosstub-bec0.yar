rule TTP_XOR_MULT_DOSStub_bec0 {
  strings:
    $key_bec0 = { ea a8 [2] 9e b0 [2] d9 b2 [2] 9e a3 [2] d0 af [2] dc a5 [2] cb ae [2] d0 e0 [2] ed }

  condition:
    any of them
}
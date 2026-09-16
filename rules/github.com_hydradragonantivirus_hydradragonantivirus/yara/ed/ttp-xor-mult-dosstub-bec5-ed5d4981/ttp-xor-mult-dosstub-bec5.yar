rule TTP_XOR_MULT_DOSStub_bec5 {
  strings:
    $key_bec5 = { ea ad [2] 9e b5 [2] d9 b7 [2] 9e a6 [2] d0 aa [2] dc a0 [2] cb ab [2] d0 e5 [2] ed }

  condition:
    any of them
}
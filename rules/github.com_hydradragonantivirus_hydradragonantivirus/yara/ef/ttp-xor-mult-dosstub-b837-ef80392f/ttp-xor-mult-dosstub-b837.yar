rule TTP_XOR_MULT_DOSStub_b837 {
  strings:
    $key_b837 = { ec 5f [2] 98 47 [2] df 45 [2] 98 54 [2] d6 58 [2] da 52 [2] cd 59 [2] d6 17 [2] eb }

  condition:
    any of them
}
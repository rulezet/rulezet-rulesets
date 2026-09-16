rule TTP_XOR_MULT_DOSStub_b8f5 {
  strings:
    $key_b8f5 = { ec 9d [2] 98 85 [2] df 87 [2] 98 96 [2] d6 9a [2] da 90 [2] cd 9b [2] d6 d5 [2] eb }

  condition:
    any of them
}
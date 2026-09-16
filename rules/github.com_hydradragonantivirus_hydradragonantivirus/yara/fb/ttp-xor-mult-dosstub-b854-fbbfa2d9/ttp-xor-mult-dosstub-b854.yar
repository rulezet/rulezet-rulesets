rule TTP_XOR_MULT_DOSStub_b854 {
  strings:
    $key_b854 = { ec 3c [2] 98 24 [2] df 26 [2] 98 37 [2] d6 3b [2] da 31 [2] cd 3a [2] d6 74 [2] eb }

  condition:
    any of them
}
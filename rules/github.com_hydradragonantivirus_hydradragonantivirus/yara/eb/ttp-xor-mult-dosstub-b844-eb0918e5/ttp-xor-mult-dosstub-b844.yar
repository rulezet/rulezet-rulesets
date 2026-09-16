rule TTP_XOR_MULT_DOSStub_b844 {
  strings:
    $key_b844 = { ec 2c [2] 98 34 [2] df 36 [2] 98 27 [2] d6 2b [2] da 21 [2] cd 2a [2] d6 64 [2] eb }

  condition:
    any of them
}
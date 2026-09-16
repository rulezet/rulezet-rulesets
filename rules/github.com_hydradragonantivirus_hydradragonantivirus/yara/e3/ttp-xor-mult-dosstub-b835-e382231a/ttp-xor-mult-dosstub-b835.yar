rule TTP_XOR_MULT_DOSStub_b835 {
  strings:
    $key_b835 = { ec 5d [2] 98 45 [2] df 47 [2] 98 56 [2] d6 5a [2] da 50 [2] cd 5b [2] d6 15 [2] eb }

  condition:
    any of them
}
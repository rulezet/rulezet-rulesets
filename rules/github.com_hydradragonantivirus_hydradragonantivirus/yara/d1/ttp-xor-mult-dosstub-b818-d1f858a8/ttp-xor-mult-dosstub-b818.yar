rule TTP_XOR_MULT_DOSStub_b818 {
  strings:
    $key_b818 = { ec 70 [2] 98 68 [2] df 6a [2] 98 7b [2] d6 77 [2] da 7d [2] cd 76 [2] d6 38 [2] eb }

  condition:
    any of them
}
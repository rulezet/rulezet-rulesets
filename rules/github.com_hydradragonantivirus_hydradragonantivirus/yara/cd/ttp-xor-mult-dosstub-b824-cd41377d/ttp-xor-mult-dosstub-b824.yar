rule TTP_XOR_MULT_DOSStub_b824 {
  strings:
    $key_b824 = { ec 4c [2] 98 54 [2] df 56 [2] 98 47 [2] d6 4b [2] da 41 [2] cd 4a [2] d6 04 [2] eb }

  condition:
    any of them
}
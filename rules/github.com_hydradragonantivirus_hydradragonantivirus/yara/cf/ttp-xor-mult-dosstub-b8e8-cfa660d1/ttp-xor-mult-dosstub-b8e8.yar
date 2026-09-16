rule TTP_XOR_MULT_DOSStub_b8e8 {
  strings:
    $key_b8e8 = { ec 80 [2] 98 98 [2] df 9a [2] 98 8b [2] d6 87 [2] da 8d [2] cd 86 [2] d6 c8 [2] eb }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b879 {
  strings:
    $key_b879 = { ec 11 [2] 98 09 [2] df 0b [2] 98 1a [2] d6 16 [2] da 1c [2] cd 17 [2] d6 59 [2] eb }

  condition:
    any of them
}
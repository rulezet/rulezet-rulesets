rule TTP_XOR_MULT_DOSStub_b813 {
  strings:
    $key_b813 = { ec 7b [2] 98 63 [2] df 61 [2] 98 70 [2] d6 7c [2] da 76 [2] cd 7d [2] d6 33 [2] eb }

  condition:
    any of them
}
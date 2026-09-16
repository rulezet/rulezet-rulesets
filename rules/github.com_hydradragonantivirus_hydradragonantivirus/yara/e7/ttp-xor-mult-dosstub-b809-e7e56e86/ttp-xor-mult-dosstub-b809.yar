rule TTP_XOR_MULT_DOSStub_b809 {
  strings:
    $key_b809 = { ec 61 [2] 98 79 [2] df 7b [2] 98 6a [2] d6 66 [2] da 6c [2] cd 67 [2] d6 29 [2] eb }

  condition:
    any of them
}
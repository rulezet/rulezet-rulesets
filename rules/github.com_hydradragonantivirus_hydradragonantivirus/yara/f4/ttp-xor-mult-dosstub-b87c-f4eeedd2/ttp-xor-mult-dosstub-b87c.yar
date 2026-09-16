rule TTP_XOR_MULT_DOSStub_b87c {
  strings:
    $key_b87c = { ec 14 [2] 98 0c [2] df 0e [2] 98 1f [2] d6 13 [2] da 19 [2] cd 12 [2] d6 5c [2] eb }

  condition:
    any of them
}
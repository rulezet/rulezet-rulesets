rule TTP_XOR_MULT_DOSStub_b82b {
  strings:
    $key_b82b = { ec 43 [2] 98 5b [2] df 59 [2] 98 48 [2] d6 44 [2] da 4e [2] cd 45 [2] d6 0b [2] eb }

  condition:
    any of them
}
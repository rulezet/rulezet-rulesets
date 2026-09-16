rule TTP_XOR_MULT_DOSStub_b82e {
  strings:
    $key_b82e = { ec 46 [2] 98 5e [2] df 5c [2] 98 4d [2] d6 41 [2] da 4b [2] cd 40 [2] d6 0e [2] eb }

  condition:
    any of them
}
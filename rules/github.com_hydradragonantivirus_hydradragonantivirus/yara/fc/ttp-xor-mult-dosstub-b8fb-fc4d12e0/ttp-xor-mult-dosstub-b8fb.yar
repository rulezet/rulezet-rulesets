rule TTP_XOR_MULT_DOSStub_b8fb {
  strings:
    $key_b8fb = { ec 93 [2] 98 8b [2] df 89 [2] 98 98 [2] d6 94 [2] da 9e [2] cd 95 [2] d6 db [2] eb }

  condition:
    any of them
}
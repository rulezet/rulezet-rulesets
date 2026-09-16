rule TTP_XOR_MULT_DOSStub_b8ec {
  strings:
    $key_b8ec = { ec 84 [2] 98 9c [2] df 9e [2] 98 8f [2] d6 83 [2] da 89 [2] cd 82 [2] d6 cc [2] eb }

  condition:
    any of them
}
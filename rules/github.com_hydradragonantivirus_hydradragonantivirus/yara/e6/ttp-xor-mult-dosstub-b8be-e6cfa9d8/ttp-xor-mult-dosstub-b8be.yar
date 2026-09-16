rule TTP_XOR_MULT_DOSStub_b8be {
  strings:
    $key_b8be = { ec d6 [2] 98 ce [2] df cc [2] 98 dd [2] d6 d1 [2] da db [2] cd d0 [2] d6 9e [2] eb }

  condition:
    any of them
}
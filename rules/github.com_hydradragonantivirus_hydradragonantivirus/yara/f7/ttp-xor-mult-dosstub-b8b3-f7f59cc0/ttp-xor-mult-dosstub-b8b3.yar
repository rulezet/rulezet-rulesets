rule TTP_XOR_MULT_DOSStub_b8b3 {
  strings:
    $key_b8b3 = { ec db [2] 98 c3 [2] df c1 [2] 98 d0 [2] d6 dc [2] da d6 [2] cd dd [2] d6 93 [2] eb }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b8f3 {
  strings:
    $key_b8f3 = { ec 9b [2] 98 83 [2] df 81 [2] 98 90 [2] d6 9c [2] da 96 [2] cd 9d [2] d6 d3 [2] eb }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b8e3 {
  strings:
    $key_b8e3 = { ec 8b [2] 98 93 [2] df 91 [2] 98 80 [2] d6 8c [2] da 86 [2] cd 8d [2] d6 c3 [2] eb }

  condition:
    any of them
}
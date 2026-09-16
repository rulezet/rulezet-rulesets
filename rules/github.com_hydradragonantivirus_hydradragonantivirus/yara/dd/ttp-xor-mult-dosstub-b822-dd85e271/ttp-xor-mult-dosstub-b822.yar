rule TTP_XOR_MULT_DOSStub_b822 {
  strings:
    $key_b822 = { ec 4a [2] 98 52 [2] df 50 [2] 98 41 [2] d6 4d [2] da 47 [2] cd 4c [2] d6 02 [2] eb }

  condition:
    any of them
}
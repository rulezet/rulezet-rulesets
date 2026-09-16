rule TTP_XOR_MULT_DOSStub_b87f {
  strings:
    $key_b87f = { ec 17 [2] 98 0f [2] df 0d [2] 98 1c [2] d6 10 [2] da 1a [2] cd 11 [2] d6 5f [2] eb }

  condition:
    any of them
}
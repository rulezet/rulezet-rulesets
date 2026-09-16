rule TTP_XOR_MULT_DOSStub_b8ed {
  strings:
    $key_b8ed = { ec 85 [2] 98 9d [2] df 9f [2] 98 8e [2] d6 82 [2] da 88 [2] cd 83 [2] d6 cd [2] eb }

  condition:
    any of them
}
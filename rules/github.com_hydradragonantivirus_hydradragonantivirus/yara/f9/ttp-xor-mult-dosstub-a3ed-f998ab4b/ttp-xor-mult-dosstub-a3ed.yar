rule TTP_XOR_MULT_DOSStub_a3ed {
  strings:
    $key_a3ed = { f7 85 [2] 83 9d [2] c4 9f [2] 83 8e [2] cd 82 [2] c1 88 [2] d6 83 [2] cd cd [2] f0 }

  condition:
    any of them
}
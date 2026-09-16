rule TTP_XOR_MULT_DOSStub_a309 {
  strings:
    $key_a309 = { f7 61 [2] 83 79 [2] c4 7b [2] 83 6a [2] cd 66 [2] c1 6c [2] d6 67 [2] cd 29 [2] f0 }

  condition:
    any of them
}
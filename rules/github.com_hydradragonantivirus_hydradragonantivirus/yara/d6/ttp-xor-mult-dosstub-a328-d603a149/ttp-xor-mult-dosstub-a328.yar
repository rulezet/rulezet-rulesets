rule TTP_XOR_MULT_DOSStub_a328 {
  strings:
    $key_a328 = { f7 40 [2] 83 58 [2] c4 5a [2] 83 4b [2] cd 47 [2] c1 4d [2] d6 46 [2] cd 08 [2] f0 }

  condition:
    any of them
}
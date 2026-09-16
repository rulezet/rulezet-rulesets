rule TTP_XOR_MULT_DOSStub_a35f {
  strings:
    $key_a35f = { f7 37 [2] 83 2f [2] c4 2d [2] 83 3c [2] cd 30 [2] c1 3a [2] d6 31 [2] cd 7f [2] f0 }

  condition:
    any of them
}
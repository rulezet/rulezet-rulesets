rule TTP_XOR_MULT_DOSStub_a36c {
  strings:
    $key_a36c = { f7 04 [2] 83 1c [2] c4 1e [2] 83 0f [2] cd 03 [2] c1 09 [2] d6 02 [2] cd 4c [2] f0 }

  condition:
    any of them
}
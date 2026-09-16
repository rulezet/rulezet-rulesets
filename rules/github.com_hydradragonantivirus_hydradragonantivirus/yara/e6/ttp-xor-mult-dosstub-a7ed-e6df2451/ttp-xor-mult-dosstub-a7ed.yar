rule TTP_XOR_MULT_DOSStub_a7ed {
  strings:
    $key_a7ed = { f3 85 [2] 87 9d [2] c0 9f [2] 87 8e [2] c9 82 [2] c5 88 [2] d2 83 [2] c9 cd [2] f4 }

  condition:
    any of them
}
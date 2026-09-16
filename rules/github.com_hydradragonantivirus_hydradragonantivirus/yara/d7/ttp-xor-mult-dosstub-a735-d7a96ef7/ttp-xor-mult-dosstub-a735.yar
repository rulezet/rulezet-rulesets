rule TTP_XOR_MULT_DOSStub_a735 {
  strings:
    $key_a735 = { f3 5d [2] 87 45 [2] c0 47 [2] 87 56 [2] c9 5a [2] c5 50 [2] d2 5b [2] c9 15 [2] f4 }

  condition:
    any of them
}
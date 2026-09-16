rule TTP_XOR_MULT_DOSStub_a729 {
  strings:
    $key_a729 = { f3 41 [2] 87 59 [2] c0 5b [2] 87 4a [2] c9 46 [2] c5 4c [2] d2 47 [2] c9 09 [2] f4 }

  condition:
    any of them
}
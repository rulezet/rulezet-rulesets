rule TTP_XOR_MULT_DOSStub_a723 {
  strings:
    $key_a723 = { f3 4b [2] 87 53 [2] c0 51 [2] 87 40 [2] c9 4c [2] c5 46 [2] d2 4d [2] c9 03 [2] f4 }

  condition:
    any of them
}
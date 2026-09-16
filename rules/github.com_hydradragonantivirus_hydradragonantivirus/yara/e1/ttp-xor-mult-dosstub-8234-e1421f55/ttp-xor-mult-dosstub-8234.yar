rule TTP_XOR_MULT_DOSStub_8234 {
  strings:
    $key_8234 = { d6 5c [2] a2 44 [2] e5 46 [2] a2 57 [2] ec 5b [2] e0 51 [2] f7 5a [2] ec 14 [2] d1 }

  condition:
    any of them
}
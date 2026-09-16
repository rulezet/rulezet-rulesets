rule TTP_XOR_MULT_DOSStub_8224 {
  strings:
    $key_8224 = { d6 4c [2] a2 54 [2] e5 56 [2] a2 47 [2] ec 4b [2] e0 41 [2] f7 4a [2] ec 04 [2] d1 }

  condition:
    any of them
}
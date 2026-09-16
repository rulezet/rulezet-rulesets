rule TTP_XOR_MULT_DOSStub_8225 {
  strings:
    $key_8225 = { d6 4d [2] a2 55 [2] e5 57 [2] a2 46 [2] ec 4a [2] e0 40 [2] f7 4b [2] ec 05 [2] d1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8228 {
  strings:
    $key_8228 = { d6 40 [2] a2 58 [2] e5 5a [2] a2 4b [2] ec 47 [2] e0 4d [2] f7 46 [2] ec 08 [2] d1 }

  condition:
    any of them
}
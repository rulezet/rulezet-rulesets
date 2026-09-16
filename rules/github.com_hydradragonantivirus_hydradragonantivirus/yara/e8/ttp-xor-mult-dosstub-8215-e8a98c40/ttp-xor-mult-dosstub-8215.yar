rule TTP_XOR_MULT_DOSStub_8215 {
  strings:
    $key_8215 = { d6 7d [2] a2 65 [2] e5 67 [2] a2 76 [2] ec 7a [2] e0 70 [2] f7 7b [2] ec 35 [2] d1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8247 {
  strings:
    $key_8247 = { d6 2f [2] a2 37 [2] e5 35 [2] a2 24 [2] ec 28 [2] e0 22 [2] f7 29 [2] ec 67 [2] d1 }

  condition:
    any of them
}
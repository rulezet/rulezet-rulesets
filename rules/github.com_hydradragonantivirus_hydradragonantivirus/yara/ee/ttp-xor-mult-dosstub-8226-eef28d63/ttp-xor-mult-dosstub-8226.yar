rule TTP_XOR_MULT_DOSStub_8226 {
  strings:
    $key_8226 = { d6 4e [2] a2 56 [2] e5 54 [2] a2 45 [2] ec 49 [2] e0 43 [2] f7 48 [2] ec 06 [2] d1 }

  condition:
    any of them
}
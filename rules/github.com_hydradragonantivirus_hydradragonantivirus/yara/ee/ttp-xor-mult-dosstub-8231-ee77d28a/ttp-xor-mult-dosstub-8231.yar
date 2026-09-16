rule TTP_XOR_MULT_DOSStub_8231 {
  strings:
    $key_8231 = { d6 59 [2] a2 41 [2] e5 43 [2] a2 52 [2] ec 5e [2] e0 54 [2] f7 5f [2] ec 11 [2] d1 }

  condition:
    any of them
}
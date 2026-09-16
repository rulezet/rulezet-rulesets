rule TTP_XOR_MULT_DOSStub_8241 {
  strings:
    $key_8241 = { d6 29 [2] a2 31 [2] e5 33 [2] a2 22 [2] ec 2e [2] e0 24 [2] f7 2f [2] ec 61 [2] d1 }

  condition:
    any of them
}
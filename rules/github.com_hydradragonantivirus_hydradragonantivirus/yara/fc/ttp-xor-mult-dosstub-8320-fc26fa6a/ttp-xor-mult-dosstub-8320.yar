rule TTP_XOR_MULT_DOSStub_8320 {
  strings:
    $key_8320 = { d7 48 [2] a3 50 [2] e4 52 [2] a3 43 [2] ed 4f [2] e1 45 [2] f6 4e [2] ed 00 [2] d0 }

  condition:
    any of them
}
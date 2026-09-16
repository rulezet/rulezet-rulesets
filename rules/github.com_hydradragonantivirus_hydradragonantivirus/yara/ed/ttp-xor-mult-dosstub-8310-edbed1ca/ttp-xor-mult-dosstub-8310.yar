rule TTP_XOR_MULT_DOSStub_8310 {
  strings:
    $key_8310 = { d7 78 [2] a3 60 [2] e4 62 [2] a3 73 [2] ed 7f [2] e1 75 [2] f6 7e [2] ed 30 [2] d0 }

  condition:
    any of them
}
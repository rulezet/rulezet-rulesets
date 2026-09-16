rule TTP_XOR_MULT_DOSStub_8260 {
  strings:
    $key_8260 = { d6 08 [2] a2 10 [2] e5 12 [2] a2 03 [2] ec 0f [2] e0 05 [2] f7 0e [2] ec 40 [2] d1 }

  condition:
    any of them
}
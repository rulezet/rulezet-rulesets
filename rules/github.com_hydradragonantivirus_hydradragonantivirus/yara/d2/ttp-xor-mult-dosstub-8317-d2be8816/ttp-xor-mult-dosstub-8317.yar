rule TTP_XOR_MULT_DOSStub_8317 {
  strings:
    $key_8317 = { d7 7f [2] a3 67 [2] e4 65 [2] a3 74 [2] ed 78 [2] e1 72 [2] f6 79 [2] ed 37 [2] d0 }

  condition:
    any of them
}
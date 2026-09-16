rule TTP_XOR_MULT_DOSStub_8321 {
  strings:
    $key_8321 = { d7 49 [2] a3 51 [2] e4 53 [2] a3 42 [2] ed 4e [2] e1 44 [2] f6 4f [2] ed 01 [2] d0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8227 {
  strings:
    $key_8227 = { d6 4f [2] a2 57 [2] e5 55 [2] a2 44 [2] ec 48 [2] e0 42 [2] f7 49 [2] ec 07 [2] d1 }

  condition:
    any of them
}
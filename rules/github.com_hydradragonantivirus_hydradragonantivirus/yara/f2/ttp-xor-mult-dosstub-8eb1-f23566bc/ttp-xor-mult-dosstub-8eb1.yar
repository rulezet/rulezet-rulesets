rule TTP_XOR_MULT_DOSStub_8eb1 {
  strings:
    $key_8eb1 = { da d9 [2] ae c1 [2] e9 c3 [2] ae d2 [2] e0 de [2] ec d4 [2] fb df [2] e0 91 [2] dd }

  condition:
    any of them
}
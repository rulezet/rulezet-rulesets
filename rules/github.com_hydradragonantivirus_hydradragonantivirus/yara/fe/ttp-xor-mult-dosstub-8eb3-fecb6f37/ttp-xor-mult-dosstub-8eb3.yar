rule TTP_XOR_MULT_DOSStub_8eb3 {
  strings:
    $key_8eb3 = { da db [2] ae c3 [2] e9 c1 [2] ae d0 [2] e0 dc [2] ec d6 [2] fb dd [2] e0 93 [2] dd }

  condition:
    any of them
}
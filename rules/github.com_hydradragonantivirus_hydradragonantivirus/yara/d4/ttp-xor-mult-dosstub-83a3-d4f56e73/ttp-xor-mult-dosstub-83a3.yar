rule TTP_XOR_MULT_DOSStub_83a3 {
  strings:
    $key_83a3 = { d7 cb [2] a3 d3 [2] e4 d1 [2] a3 c0 [2] ed cc [2] e1 c6 [2] f6 cd [2] ed 83 [2] d0 }

  condition:
    any of them
}
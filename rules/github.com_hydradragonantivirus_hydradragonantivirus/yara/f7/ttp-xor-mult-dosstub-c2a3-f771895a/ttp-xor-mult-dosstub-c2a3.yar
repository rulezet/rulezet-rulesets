rule TTP_XOR_MULT_DOSStub_c2a3 {
  strings:
    $key_c2a3 = { 96 cb [2] e2 d3 [2] a5 d1 [2] e2 c0 [2] ac cc [2] a0 c6 [2] b7 cd [2] ac 83 [2] 91 }

  condition:
    any of them
}
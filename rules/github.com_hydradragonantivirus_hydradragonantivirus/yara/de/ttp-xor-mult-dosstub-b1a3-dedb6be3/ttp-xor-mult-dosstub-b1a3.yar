rule TTP_XOR_MULT_DOSStub_b1a3 {
  strings:
    $key_b1a3 = { e5 cb [2] 91 d3 [2] d6 d1 [2] 91 c0 [2] df cc [2] d3 c6 [2] c4 cd [2] df 83 [2] e2 }

  condition:
    any of them
}
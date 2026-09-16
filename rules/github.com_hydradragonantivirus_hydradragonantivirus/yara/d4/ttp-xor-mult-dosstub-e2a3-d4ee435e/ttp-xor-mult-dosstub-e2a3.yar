rule TTP_XOR_MULT_DOSStub_e2a3 {
  strings:
    $key_e2a3 = { b6 cb [2] c2 d3 [2] 85 d1 [2] c2 c0 [2] 8c cc [2] 80 c6 [2] 97 cd [2] 8c 83 [2] b1 }

  condition:
    any of them
}
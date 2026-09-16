rule TTP_XOR_MULT_DOSStub_94d3 {
  strings:
    $key_94d3 = { c0 bb [2] b4 a3 [2] f3 a1 [2] b4 b0 [2] fa bc [2] f6 b6 [2] e1 bd [2] fa f3 [2] c7 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_cad2 {
  strings:
    $key_cad2 = { 9e ba [2] ea a2 [2] ad a0 [2] ea b1 [2] a4 bd [2] a8 b7 [2] bf bc [2] a4 f2 [2] 99 }

  condition:
    any of them
}
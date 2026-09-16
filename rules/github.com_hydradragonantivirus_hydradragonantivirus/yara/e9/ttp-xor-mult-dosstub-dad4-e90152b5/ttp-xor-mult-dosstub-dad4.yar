rule TTP_XOR_MULT_DOSStub_dad4 {
  strings:
    $key_dad4 = { 8e bc [2] fa a4 [2] bd a6 [2] fa b7 [2] b4 bb [2] b8 b1 [2] af ba [2] b4 f4 [2] 89 }

  condition:
    any of them
}
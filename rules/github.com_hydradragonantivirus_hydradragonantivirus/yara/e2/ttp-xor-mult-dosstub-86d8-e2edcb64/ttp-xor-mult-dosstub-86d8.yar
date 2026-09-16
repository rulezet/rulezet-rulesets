rule TTP_XOR_MULT_DOSStub_86d8 {
  strings:
    $key_86d8 = { d2 b0 [2] a6 a8 [2] e1 aa [2] a6 bb [2] e8 b7 [2] e4 bd [2] f3 b6 [2] e8 f8 [2] d5 }

  condition:
    any of them
}
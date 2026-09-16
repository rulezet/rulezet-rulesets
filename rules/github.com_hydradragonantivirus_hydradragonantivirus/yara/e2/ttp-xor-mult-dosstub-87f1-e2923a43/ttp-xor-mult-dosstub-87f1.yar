rule TTP_XOR_MULT_DOSStub_87f1 {
  strings:
    $key_87f1 = { d3 99 [2] a7 81 [2] e0 83 [2] a7 92 [2] e9 9e [2] e5 94 [2] f2 9f [2] e9 d1 [2] d4 }

  condition:
    any of them
}
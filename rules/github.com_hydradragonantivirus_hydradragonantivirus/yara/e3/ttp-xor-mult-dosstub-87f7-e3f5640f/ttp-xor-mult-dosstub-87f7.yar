rule TTP_XOR_MULT_DOSStub_87f7 {
  strings:
    $key_87f7 = { d3 9f [2] a7 87 [2] e0 85 [2] a7 94 [2] e9 98 [2] e5 92 [2] f2 99 [2] e9 d7 [2] d4 }

  condition:
    any of them
}
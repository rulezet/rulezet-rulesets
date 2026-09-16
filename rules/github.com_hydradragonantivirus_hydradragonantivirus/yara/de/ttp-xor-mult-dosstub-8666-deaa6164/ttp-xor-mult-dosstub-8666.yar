rule TTP_XOR_MULT_DOSStub_8666 {
  strings:
    $key_8666 = { d2 0e [2] a6 16 [2] e1 14 [2] a6 05 [2] e8 09 [2] e4 03 [2] f3 08 [2] e8 46 [2] d5 }

  condition:
    any of them
}
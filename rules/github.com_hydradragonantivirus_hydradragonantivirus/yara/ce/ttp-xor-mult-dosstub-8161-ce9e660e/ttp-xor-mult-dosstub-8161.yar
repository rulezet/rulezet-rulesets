rule TTP_XOR_MULT_DOSStub_8161 {
  strings:
    $key_8161 = { d5 09 [2] a1 11 [2] e6 13 [2] a1 02 [2] ef 0e [2] e3 04 [2] f4 0f [2] ef 41 [2] d2 }

  condition:
    any of them
}
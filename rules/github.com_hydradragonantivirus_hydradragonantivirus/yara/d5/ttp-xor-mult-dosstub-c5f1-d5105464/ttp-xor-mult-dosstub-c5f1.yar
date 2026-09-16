rule TTP_XOR_MULT_DOSStub_c5f1 {
  strings:
    $key_c5f1 = { 91 99 [2] e5 81 [2] a2 83 [2] e5 92 [2] ab 9e [2] a7 94 [2] b0 9f [2] ab d1 [2] 96 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c5f0 {
  strings:
    $key_c5f0 = { 91 98 [2] e5 80 [2] a2 82 [2] e5 93 [2] ab 9f [2] a7 95 [2] b0 9e [2] ab d0 [2] 96 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c550 {
  strings:
    $key_c550 = { 91 38 [2] e5 20 [2] a2 22 [2] e5 33 [2] ab 3f [2] a7 35 [2] b0 3e [2] ab 70 [2] 96 }

  condition:
    any of them
}
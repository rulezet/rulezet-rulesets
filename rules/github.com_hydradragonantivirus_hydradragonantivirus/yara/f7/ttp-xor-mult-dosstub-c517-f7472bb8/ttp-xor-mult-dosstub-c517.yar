rule TTP_XOR_MULT_DOSStub_c517 {
  strings:
    $key_c517 = { 91 7f [2] e5 67 [2] a2 65 [2] e5 74 [2] ab 78 [2] a7 72 [2] b0 79 [2] ab 37 [2] 96 }

  condition:
    any of them
}
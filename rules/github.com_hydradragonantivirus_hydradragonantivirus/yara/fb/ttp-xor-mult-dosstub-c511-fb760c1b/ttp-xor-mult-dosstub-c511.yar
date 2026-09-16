rule TTP_XOR_MULT_DOSStub_c511 {
  strings:
    $key_c511 = { 91 79 [2] e5 61 [2] a2 63 [2] e5 72 [2] ab 7e [2] a7 74 [2] b0 7f [2] ab 31 [2] 96 }

  condition:
    any of them
}
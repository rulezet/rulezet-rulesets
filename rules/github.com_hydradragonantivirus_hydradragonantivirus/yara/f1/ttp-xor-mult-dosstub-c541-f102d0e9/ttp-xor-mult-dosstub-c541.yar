rule TTP_XOR_MULT_DOSStub_c541 {
  strings:
    $key_c541 = { 91 29 [2] e5 31 [2] a2 33 [2] e5 22 [2] ab 2e [2] a7 24 [2] b0 2f [2] ab 61 [2] 96 }

  condition:
    any of them
}
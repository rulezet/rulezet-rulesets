rule TTP_XOR_MULT_DOSStub_c5e3 {
  strings:
    $key_c5e3 = { 91 8b [2] e5 93 [2] a2 91 [2] e5 80 [2] ab 8c [2] a7 86 [2] b0 8d [2] ab c3 [2] 96 }

  condition:
    any of them
}
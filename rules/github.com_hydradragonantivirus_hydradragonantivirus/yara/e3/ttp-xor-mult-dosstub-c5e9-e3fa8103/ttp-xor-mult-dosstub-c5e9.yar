rule TTP_XOR_MULT_DOSStub_c5e9 {
  strings:
    $key_c5e9 = { 91 81 [2] e5 99 [2] a2 9b [2] e5 8a [2] ab 86 [2] a7 8c [2] b0 87 [2] ab c9 [2] 96 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c119 {
  strings:
    $key_c119 = { 95 71 [2] e1 69 [2] a6 6b [2] e1 7a [2] af 76 [2] a3 7c [2] b4 77 [2] af 39 [2] 92 }

  condition:
    any of them
}
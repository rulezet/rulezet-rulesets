rule TTP_XOR_MULT_DOSStub_c609 {
  strings:
    $key_c609 = { 92 61 [2] e6 79 [2] a1 7b [2] e6 6a [2] a8 66 [2] a4 6c [2] b3 67 [2] a8 29 [2] 95 }

  condition:
    any of them
}
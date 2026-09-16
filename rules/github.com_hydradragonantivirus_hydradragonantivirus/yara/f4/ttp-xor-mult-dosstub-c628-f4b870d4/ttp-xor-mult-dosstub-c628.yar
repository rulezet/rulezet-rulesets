rule TTP_XOR_MULT_DOSStub_c628 {
  strings:
    $key_c628 = { 92 40 [2] e6 58 [2] a1 5a [2] e6 4b [2] a8 47 [2] a4 4d [2] b3 46 [2] a8 08 [2] 95 }

  condition:
    any of them
}
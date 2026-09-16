rule TTP_XOR_MULT_DOSStub_c629 {
  strings:
    $key_c629 = { 92 41 [2] e6 59 [2] a1 5b [2] e6 4a [2] a8 46 [2] a4 4c [2] b3 47 [2] a8 09 [2] 95 }

  condition:
    any of them
}
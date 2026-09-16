rule TTP_XOR_MULT_DOSStub_c6f2 {
  strings:
    $key_c6f2 = { 92 9a [2] e6 82 [2] a1 80 [2] e6 91 [2] a8 9d [2] a4 97 [2] b3 9c [2] a8 d2 [2] 95 }

  condition:
    any of them
}
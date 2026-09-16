rule TTP_XOR_MULT_DOSStub_c613 {
  strings:
    $key_c613 = { 92 7b [2] e6 63 [2] a1 61 [2] e6 70 [2] a8 7c [2] a4 76 [2] b3 7d [2] a8 33 [2] 95 }

  condition:
    any of them
}
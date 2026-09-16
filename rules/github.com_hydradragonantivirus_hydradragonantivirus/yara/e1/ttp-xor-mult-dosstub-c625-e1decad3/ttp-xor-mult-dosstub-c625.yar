rule TTP_XOR_MULT_DOSStub_c625 {
  strings:
    $key_c625 = { 92 4d [2] e6 55 [2] a1 57 [2] e6 46 [2] a8 4a [2] a4 40 [2] b3 4b [2] a8 05 [2] 95 }

  condition:
    any of them
}
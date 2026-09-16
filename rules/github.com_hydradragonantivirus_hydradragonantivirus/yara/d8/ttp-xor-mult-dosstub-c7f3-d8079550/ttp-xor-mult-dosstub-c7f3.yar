rule TTP_XOR_MULT_DOSStub_c7f3 {
  strings:
    $key_c7f3 = { 93 9b [2] e7 83 [2] a0 81 [2] e7 90 [2] a9 9c [2] a5 96 [2] b2 9d [2] a9 d3 [2] 94 }

  condition:
    any of them
}
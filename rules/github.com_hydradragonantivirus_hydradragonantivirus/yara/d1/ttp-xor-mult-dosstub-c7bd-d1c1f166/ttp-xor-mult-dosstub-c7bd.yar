rule TTP_XOR_MULT_DOSStub_c7bd {
  strings:
    $key_c7bd = { 93 d5 [2] e7 cd [2] a0 cf [2] e7 de [2] a9 d2 [2] a5 d8 [2] b2 d3 [2] a9 9d [2] 94 }

  condition:
    any of them
}
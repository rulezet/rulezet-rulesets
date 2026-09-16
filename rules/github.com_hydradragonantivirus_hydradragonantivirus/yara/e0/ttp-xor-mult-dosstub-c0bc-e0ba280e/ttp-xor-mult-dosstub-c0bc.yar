rule TTP_XOR_MULT_DOSStub_c0bc {
  strings:
    $key_c0bc = { 94 d4 [2] e0 cc [2] a7 ce [2] e0 df [2] ae d3 [2] a2 d9 [2] b5 d2 [2] ae 9c [2] 93 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_86bc {
  strings:
    $key_86bc = { d2 d4 [2] a6 cc [2] e1 ce [2] a6 df [2] e8 d3 [2] e4 d9 [2] f3 d2 [2] e8 9c [2] d5 }

  condition:
    any of them
}
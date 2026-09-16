rule TTP_XOR_MULT_DOSStub_97bc {
  strings:
    $key_97bc = { c3 d4 [2] b7 cc [2] f0 ce [2] b7 df [2] f9 d3 [2] f5 d9 [2] e2 d2 [2] f9 9c [2] c4 }

  condition:
    any of them
}
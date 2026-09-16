rule TTP_XOR_MULT_DOSStub_d1bc {
  strings:
    $key_d1bc = { 85 d4 [2] f1 cc [2] b6 ce [2] f1 df [2] bf d3 [2] b3 d9 [2] a4 d2 [2] bf 9c [2] 82 }

  condition:
    any of them
}
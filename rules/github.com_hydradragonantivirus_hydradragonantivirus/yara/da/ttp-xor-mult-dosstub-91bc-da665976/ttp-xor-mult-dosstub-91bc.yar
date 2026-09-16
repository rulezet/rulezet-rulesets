rule TTP_XOR_MULT_DOSStub_91bc {
  strings:
    $key_91bc = { c5 d4 [2] b1 cc [2] f6 ce [2] b1 df [2] ff d3 [2] f3 d9 [2] e4 d2 [2] ff 9c [2] c2 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_94bc {
  strings:
    $key_94bc = { c0 d4 [2] b4 cc [2] f3 ce [2] b4 df [2] fa d3 [2] f6 d9 [2] e1 d2 [2] fa 9c [2] c7 }

  condition:
    any of them
}
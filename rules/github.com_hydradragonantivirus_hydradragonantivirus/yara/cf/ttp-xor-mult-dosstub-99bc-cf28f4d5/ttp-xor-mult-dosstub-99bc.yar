rule TTP_XOR_MULT_DOSStub_99bc {
  strings:
    $key_99bc = { cd d4 [2] b9 cc [2] fe ce [2] b9 df [2] f7 d3 [2] fb d9 [2] ec d2 [2] f7 9c [2] ca }

  condition:
    any of them
}
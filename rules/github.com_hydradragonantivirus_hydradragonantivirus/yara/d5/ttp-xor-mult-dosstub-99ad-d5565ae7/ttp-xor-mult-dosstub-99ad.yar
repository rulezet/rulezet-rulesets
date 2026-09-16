rule TTP_XOR_MULT_DOSStub_99ad {
  strings:
    $key_99ad = { cd c5 [2] b9 dd [2] fe df [2] b9 ce [2] f7 c2 [2] fb c8 [2] ec c3 [2] f7 8d [2] ca }

  condition:
    any of them
}
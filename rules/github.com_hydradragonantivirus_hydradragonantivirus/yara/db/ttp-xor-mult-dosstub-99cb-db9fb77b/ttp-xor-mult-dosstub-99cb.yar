rule TTP_XOR_MULT_DOSStub_99cb {
  strings:
    $key_99cb = { cd a3 [2] b9 bb [2] fe b9 [2] b9 a8 [2] f7 a4 [2] fb ae [2] ec a5 [2] f7 eb [2] ca }

  condition:
    any of them
}
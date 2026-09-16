rule TTP_XOR_MULT_DOSStub_99e6 {
  strings:
    $key_99e6 = { cd 8e [2] b9 96 [2] fe 94 [2] b9 85 [2] f7 89 [2] fb 83 [2] ec 88 [2] f7 c6 [2] ca }

  condition:
    any of them
}
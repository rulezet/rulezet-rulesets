rule TTP_XOR_MULT_DOSStub_99f1 {
  strings:
    $key_99f1 = { cd 99 [2] b9 81 [2] fe 83 [2] b9 92 [2] f7 9e [2] fb 94 [2] ec 9f [2] f7 d1 [2] ca }

  condition:
    any of them
}
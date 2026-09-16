rule TTP_XOR_MULT_DOSStub_99f0 {
  strings:
    $key_99f0 = { cd 98 [2] b9 80 [2] fe 82 [2] b9 93 [2] f7 9f [2] fb 95 [2] ec 9e [2] f7 d0 [2] ca }

  condition:
    any of them
}
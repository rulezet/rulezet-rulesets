rule TTP_XOR_MULT_DOSStub_99e9 {
  strings:
    $key_99e9 = { cd 81 [2] b9 99 [2] fe 9b [2] b9 8a [2] f7 86 [2] fb 8c [2] ec 87 [2] f7 c9 [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9914 {
  strings:
    $key_9914 = { cd 7c [2] b9 64 [2] fe 66 [2] b9 77 [2] f7 7b [2] fb 71 [2] ec 7a [2] f7 34 [2] ca }

  condition:
    any of them
}
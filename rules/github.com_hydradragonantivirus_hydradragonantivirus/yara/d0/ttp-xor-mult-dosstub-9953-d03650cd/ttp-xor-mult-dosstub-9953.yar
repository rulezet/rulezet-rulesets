rule TTP_XOR_MULT_DOSStub_9953 {
  strings:
    $key_9953 = { cd 3b [2] b9 23 [2] fe 21 [2] b9 30 [2] f7 3c [2] fb 36 [2] ec 3d [2] f7 73 [2] ca }

  condition:
    any of them
}
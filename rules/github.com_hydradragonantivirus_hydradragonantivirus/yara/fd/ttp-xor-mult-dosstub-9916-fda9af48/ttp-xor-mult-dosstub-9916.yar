rule TTP_XOR_MULT_DOSStub_9916 {
  strings:
    $key_9916 = { cd 7e [2] b9 66 [2] fe 64 [2] b9 75 [2] f7 79 [2] fb 73 [2] ec 78 [2] f7 36 [2] ca }

  condition:
    any of them
}
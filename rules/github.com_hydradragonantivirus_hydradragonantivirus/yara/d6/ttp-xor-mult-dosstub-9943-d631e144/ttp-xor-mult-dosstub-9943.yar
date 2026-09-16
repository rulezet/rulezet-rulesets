rule TTP_XOR_MULT_DOSStub_9943 {
  strings:
    $key_9943 = { cd 2b [2] b9 33 [2] fe 31 [2] b9 20 [2] f7 2c [2] fb 26 [2] ec 2d [2] f7 63 [2] ca }

  condition:
    any of them
}
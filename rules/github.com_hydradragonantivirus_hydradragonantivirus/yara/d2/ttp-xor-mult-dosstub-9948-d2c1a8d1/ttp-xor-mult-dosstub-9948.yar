rule TTP_XOR_MULT_DOSStub_9948 {
  strings:
    $key_9948 = { cd 20 [2] b9 38 [2] fe 3a [2] b9 2b [2] f7 27 [2] fb 2d [2] ec 26 [2] f7 68 [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9958 {
  strings:
    $key_9958 = { cd 30 [2] b9 28 [2] fe 2a [2] b9 3b [2] f7 37 [2] fb 3d [2] ec 36 [2] f7 78 [2] ca }

  condition:
    any of them
}
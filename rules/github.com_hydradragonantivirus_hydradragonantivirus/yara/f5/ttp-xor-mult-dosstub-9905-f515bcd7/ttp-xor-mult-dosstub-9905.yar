rule TTP_XOR_MULT_DOSStub_9905 {
  strings:
    $key_9905 = { cd 6d [2] b9 75 [2] fe 77 [2] b9 66 [2] f7 6a [2] fb 60 [2] ec 6b [2] f7 25 [2] ca }

  condition:
    any of them
}
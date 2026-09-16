rule TTP_XOR_MULT_DOSStub_9924 {
  strings:
    $key_9924 = { cd 4c [2] b9 54 [2] fe 56 [2] b9 47 [2] f7 4b [2] fb 41 [2] ec 4a [2] f7 04 [2] ca }

  condition:
    any of them
}
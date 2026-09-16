rule TTP_XOR_MULT_DOSStub_9908 {
  strings:
    $key_9908 = { cd 60 [2] b9 78 [2] fe 7a [2] b9 6b [2] f7 67 [2] fb 6d [2] ec 66 [2] f7 28 [2] ca }

  condition:
    any of them
}
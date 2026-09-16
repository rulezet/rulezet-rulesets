rule TTP_XOR_MULT_DOSStub_9965 {
  strings:
    $key_9965 = { cd 0d [2] b9 15 [2] fe 17 [2] b9 06 [2] f7 0a [2] fb 00 [2] ec 0b [2] f7 45 [2] ca }

  condition:
    any of them
}
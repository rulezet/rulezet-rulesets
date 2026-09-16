rule TTP_XOR_MULT_DOSStub_9963 {
  strings:
    $key_9963 = { cd 0b [2] b9 13 [2] fe 11 [2] b9 00 [2] f7 0c [2] fb 06 [2] ec 0d [2] f7 43 [2] ca }

  condition:
    any of them
}
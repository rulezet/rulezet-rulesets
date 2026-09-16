rule TTP_XOR_MULT_DOSStub_9949 {
  strings:
    $key_9949 = { cd 21 [2] b9 39 [2] fe 3b [2] b9 2a [2] f7 26 [2] fb 2c [2] ec 27 [2] f7 69 [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9918 {
  strings:
    $key_9918 = { cd 70 [2] b9 68 [2] fe 6a [2] b9 7b [2] f7 77 [2] fb 7d [2] ec 76 [2] f7 38 [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9933 {
  strings:
    $key_9933 = { cd 5b [2] b9 43 [2] fe 41 [2] b9 50 [2] f7 5c [2] fb 56 [2] ec 5d [2] f7 13 [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9937 {
  strings:
    $key_9937 = { cd 5f [2] b9 47 [2] fe 45 [2] b9 54 [2] f7 58 [2] fb 52 [2] ec 59 [2] f7 17 [2] ca }

  condition:
    any of them
}
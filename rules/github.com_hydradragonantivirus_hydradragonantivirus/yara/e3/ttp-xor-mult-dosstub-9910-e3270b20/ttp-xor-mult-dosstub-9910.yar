rule TTP_XOR_MULT_DOSStub_9910 {
  strings:
    $key_9910 = { cd 78 [2] b9 60 [2] fe 62 [2] b9 73 [2] f7 7f [2] fb 75 [2] ec 7e [2] f7 30 [2] ca }

  condition:
    any of them
}
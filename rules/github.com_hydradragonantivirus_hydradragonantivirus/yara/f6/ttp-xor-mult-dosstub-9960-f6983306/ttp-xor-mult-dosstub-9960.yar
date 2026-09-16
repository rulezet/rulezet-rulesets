rule TTP_XOR_MULT_DOSStub_9960 {
  strings:
    $key_9960 = { cd 08 [2] b9 10 [2] fe 12 [2] b9 03 [2] f7 0f [2] fb 05 [2] ec 0e [2] f7 40 [2] ca }

  condition:
    any of them
}
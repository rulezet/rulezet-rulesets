rule TTP_XOR_MULT_DOSStub_9970 {
  strings:
    $key_9970 = { cd 18 [2] b9 00 [2] fe 02 [2] b9 13 [2] f7 1f [2] fb 15 [2] ec 1e [2] f7 50 [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9971 {
  strings:
    $key_9971 = { cd 19 [2] b9 01 [2] fe 03 [2] b9 12 [2] f7 1e [2] fb 14 [2] ec 1f [2] f7 51 [2] ca }

  condition:
    any of them
}
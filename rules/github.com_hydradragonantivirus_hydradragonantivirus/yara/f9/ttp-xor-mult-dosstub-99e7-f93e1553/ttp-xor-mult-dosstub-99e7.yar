rule TTP_XOR_MULT_DOSStub_99e7 {
  strings:
    $key_99e7 = { cd 8f [2] b9 97 [2] fe 95 [2] b9 84 [2] f7 88 [2] fb 82 [2] ec 89 [2] f7 c7 [2] ca }

  condition:
    any of them
}
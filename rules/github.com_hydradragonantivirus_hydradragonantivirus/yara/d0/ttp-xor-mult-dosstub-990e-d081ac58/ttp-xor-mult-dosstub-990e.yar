rule TTP_XOR_MULT_DOSStub_990e {
  strings:
    $key_990e = { cd 66 [2] b9 7e [2] fe 7c [2] b9 6d [2] f7 61 [2] fb 6b [2] ec 60 [2] f7 2e [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_995e {
  strings:
    $key_995e = { cd 36 [2] b9 2e [2] fe 2c [2] b9 3d [2] f7 31 [2] fb 3b [2] ec 30 [2] f7 7e [2] ca }

  condition:
    any of them
}
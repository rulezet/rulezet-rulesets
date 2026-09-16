rule TTP_XOR_MULT_DOSStub_993e {
  strings:
    $key_993e = { cd 56 [2] b9 4e [2] fe 4c [2] b9 5d [2] f7 51 [2] fb 5b [2] ec 50 [2] f7 1e [2] ca }

  condition:
    any of them
}
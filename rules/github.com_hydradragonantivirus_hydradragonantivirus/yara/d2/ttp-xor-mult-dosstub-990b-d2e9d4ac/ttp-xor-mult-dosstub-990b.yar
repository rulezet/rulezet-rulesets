rule TTP_XOR_MULT_DOSStub_990b {
  strings:
    $key_990b = { cd 63 [2] b9 7b [2] fe 79 [2] b9 68 [2] f7 64 [2] fb 6e [2] ec 65 [2] f7 2b [2] ca }

  condition:
    any of them
}
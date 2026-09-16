rule TTP_XOR_MULT_DOSStub_997b {
  strings:
    $key_997b = { cd 13 [2] b9 0b [2] fe 09 [2] b9 18 [2] f7 14 [2] fb 1e [2] ec 15 [2] f7 5b [2] ca }

  condition:
    any of them
}
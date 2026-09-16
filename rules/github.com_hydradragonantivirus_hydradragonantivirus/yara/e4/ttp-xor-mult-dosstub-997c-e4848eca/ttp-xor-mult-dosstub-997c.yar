rule TTP_XOR_MULT_DOSStub_997c {
  strings:
    $key_997c = { cd 14 [2] b9 0c [2] fe 0e [2] b9 1f [2] f7 13 [2] fb 19 [2] ec 12 [2] f7 5c [2] ca }

  condition:
    any of them
}
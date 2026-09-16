rule TTP_XOR_MULT_DOSStub_99eb {
  strings:
    $key_99eb = { cd 83 [2] b9 9b [2] fe 99 [2] b9 88 [2] f7 84 [2] fb 8e [2] ec 85 [2] f7 cb [2] ca }

  condition:
    any of them
}
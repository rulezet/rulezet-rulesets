rule TTP_XOR_MULT_DOSStub_99ee {
  strings:
    $key_99ee = { cd 86 [2] b9 9e [2] fe 9c [2] b9 8d [2] f7 81 [2] fb 8b [2] ec 80 [2] f7 ce [2] ca }

  condition:
    any of them
}
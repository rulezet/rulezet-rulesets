rule TTP_XOR_MULT_DOSStub_99f3 {
  strings:
    $key_99f3 = { cd 9b [2] b9 83 [2] fe 81 [2] b9 90 [2] f7 9c [2] fb 96 [2] ec 9d [2] f7 d3 [2] ca }

  condition:
    any of them
}
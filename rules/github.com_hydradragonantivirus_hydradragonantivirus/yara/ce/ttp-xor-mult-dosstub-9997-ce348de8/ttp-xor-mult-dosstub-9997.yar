rule TTP_XOR_MULT_DOSStub_9997 {
  strings:
    $key_9997 = { cd ff [2] b9 e7 [2] fe e5 [2] b9 f4 [2] f7 f8 [2] fb f2 [2] ec f9 [2] f7 b7 [2] ca }

  condition:
    any of them
}
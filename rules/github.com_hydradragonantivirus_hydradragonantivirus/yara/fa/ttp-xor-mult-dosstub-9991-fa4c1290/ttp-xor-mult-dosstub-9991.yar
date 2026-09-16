rule TTP_XOR_MULT_DOSStub_9991 {
  strings:
    $key_9991 = { cd f9 [2] b9 e1 [2] fe e3 [2] b9 f2 [2] f7 fe [2] fb f4 [2] ec ff [2] f7 b1 [2] ca }

  condition:
    any of them
}
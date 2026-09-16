rule TTP_XOR_MULT_DOSStub_9998 {
  strings:
    $key_9998 = { cd f0 [2] b9 e8 [2] fe ea [2] b9 fb [2] f7 f7 [2] fb fd [2] ec f6 [2] f7 b8 [2] ca }

  condition:
    any of them
}
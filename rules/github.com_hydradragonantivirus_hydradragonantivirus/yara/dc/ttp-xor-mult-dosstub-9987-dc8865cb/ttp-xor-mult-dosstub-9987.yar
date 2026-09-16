rule TTP_XOR_MULT_DOSStub_9987 {
  strings:
    $key_9987 = { cd ef [2] b9 f7 [2] fe f5 [2] b9 e4 [2] f7 e8 [2] fb e2 [2] ec e9 [2] f7 a7 [2] ca }

  condition:
    any of them
}
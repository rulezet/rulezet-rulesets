rule TTP_XOR_MULT_DOSStub_9981 {
  strings:
    $key_9981 = { cd e9 [2] b9 f1 [2] fe f3 [2] b9 e2 [2] f7 ee [2] fb e4 [2] ec ef [2] f7 a1 [2] ca }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9989 {
  strings:
    $key_9989 = { cd e1 [2] b9 f9 [2] fe fb [2] b9 ea [2] f7 e6 [2] fb ec [2] ec e7 [2] f7 a9 [2] ca }

  condition:
    any of them
}
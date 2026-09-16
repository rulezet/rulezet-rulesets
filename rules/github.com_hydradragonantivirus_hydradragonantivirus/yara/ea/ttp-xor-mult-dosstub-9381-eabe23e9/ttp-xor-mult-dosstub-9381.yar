rule TTP_XOR_MULT_DOSStub_9381 {
  strings:
    $key_9381 = { c7 e9 [2] b3 f1 [2] f4 f3 [2] b3 e2 [2] fd ee [2] f1 e4 [2] e6 ef [2] fd a1 [2] c0 }

  condition:
    any of them
}
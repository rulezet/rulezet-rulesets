rule TTP_XOR_MULT_DOSStub_9281 {
  strings:
    $key_9281 = { c6 e9 [2] b2 f1 [2] f5 f3 [2] b2 e2 [2] fc ee [2] f0 e4 [2] e7 ef [2] fc a1 [2] c1 }

  condition:
    any of them
}
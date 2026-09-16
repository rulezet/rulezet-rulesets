rule TTP_XOR_MULT_DOSStub_9389 {
  strings:
    $key_9389 = { c7 e1 [2] b3 f9 [2] f4 fb [2] b3 ea [2] fd e6 [2] f1 ec [2] e6 e7 [2] fd a9 [2] c0 }

  condition:
    any of them
}
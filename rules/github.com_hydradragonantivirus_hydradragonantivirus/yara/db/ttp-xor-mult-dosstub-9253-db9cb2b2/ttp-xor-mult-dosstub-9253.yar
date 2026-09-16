rule TTP_XOR_MULT_DOSStub_9253 {
  strings:
    $key_9253 = { c6 3b [2] b2 23 [2] f5 21 [2] b2 30 [2] fc 3c [2] f0 36 [2] e7 3d [2] fc 73 [2] c1 }

  condition:
    any of them
}
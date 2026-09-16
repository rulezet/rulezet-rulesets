rule TTP_XOR_MULT_DOSStub_8292 {
  strings:
    $key_8292 = { d6 fa [2] a2 e2 [2] e5 e0 [2] a2 f1 [2] ec fd [2] e0 f7 [2] f7 fc [2] ec b2 [2] d1 }

  condition:
    any of them
}
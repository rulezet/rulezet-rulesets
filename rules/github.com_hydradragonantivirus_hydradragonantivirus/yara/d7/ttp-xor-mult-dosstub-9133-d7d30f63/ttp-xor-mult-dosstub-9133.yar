rule TTP_XOR_MULT_DOSStub_9133 {
  strings:
    $key_9133 = { c5 5b [2] b1 43 [2] f6 41 [2] b1 50 [2] ff 5c [2] f3 56 [2] e4 5d [2] ff 13 [2] c2 }

  condition:
    any of them
}
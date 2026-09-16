rule TTP_XOR_MULT_DOSStub_9138 {
  strings:
    $key_9138 = { c5 50 [2] b1 48 [2] f6 4a [2] b1 5b [2] ff 57 [2] f3 5d [2] e4 56 [2] ff 18 [2] c2 }

  condition:
    any of them
}
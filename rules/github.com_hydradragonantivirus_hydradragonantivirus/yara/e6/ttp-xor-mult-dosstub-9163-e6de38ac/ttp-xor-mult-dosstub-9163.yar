rule TTP_XOR_MULT_DOSStub_9163 {
  strings:
    $key_9163 = { c5 0b [2] b1 13 [2] f6 11 [2] b1 00 [2] ff 0c [2] f3 06 [2] e4 0d [2] ff 43 [2] c2 }

  condition:
    any of them
}
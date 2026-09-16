rule TTP_XOR_MULT_DOSStub_9069 {
  strings:
    $key_9069 = { c4 01 [2] b0 19 [2] f7 1b [2] b0 0a [2] fe 06 [2] f2 0c [2] e5 07 [2] fe 49 [2] c3 }

  condition:
    any of them
}
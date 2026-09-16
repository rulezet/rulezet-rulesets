rule TTP_XOR_MULT_DOSStub_9064 {
  strings:
    $key_9064 = { c4 0c [2] b0 14 [2] f7 16 [2] b0 07 [2] fe 0b [2] f2 01 [2] e5 0a [2] fe 44 [2] c3 }

  condition:
    any of them
}
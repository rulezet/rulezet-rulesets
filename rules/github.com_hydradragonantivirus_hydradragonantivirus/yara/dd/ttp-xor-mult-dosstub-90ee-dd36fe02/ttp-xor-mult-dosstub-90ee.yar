rule TTP_XOR_MULT_DOSStub_90ee {
  strings:
    $key_90ee = { c4 86 [2] b0 9e [2] f7 9c [2] b0 8d [2] fe 81 [2] f2 8b [2] e5 80 [2] fe ce [2] c3 }

  condition:
    any of them
}
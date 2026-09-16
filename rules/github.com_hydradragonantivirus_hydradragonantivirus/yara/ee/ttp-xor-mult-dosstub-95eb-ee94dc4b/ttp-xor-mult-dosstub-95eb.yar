rule TTP_XOR_MULT_DOSStub_95eb {
  strings:
    $key_95eb = { c1 83 [2] b5 9b [2] f2 99 [2] b5 88 [2] fb 84 [2] f7 8e [2] e0 85 [2] fb cb [2] c6 }

  condition:
    any of them
}
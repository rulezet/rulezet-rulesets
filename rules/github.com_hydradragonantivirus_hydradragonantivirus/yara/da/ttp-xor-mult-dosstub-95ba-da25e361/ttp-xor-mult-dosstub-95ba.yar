rule TTP_XOR_MULT_DOSStub_95ba {
  strings:
    $key_95ba = { c1 d2 [2] b5 ca [2] f2 c8 [2] b5 d9 [2] fb d5 [2] f7 df [2] e0 d4 [2] fb 9a [2] c6 }

  condition:
    any of them
}
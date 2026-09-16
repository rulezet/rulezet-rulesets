rule TTP_XOR_MULT_DOSStub_9561 {
  strings:
    $key_9561 = { c1 09 [2] b5 11 [2] f2 13 [2] b5 02 [2] fb 0e [2] f7 04 [2] e0 0f [2] fb 41 [2] c6 }

  condition:
    any of them
}
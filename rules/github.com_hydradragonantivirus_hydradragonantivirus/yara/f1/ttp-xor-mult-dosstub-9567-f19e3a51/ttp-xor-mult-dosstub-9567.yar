rule TTP_XOR_MULT_DOSStub_9567 {
  strings:
    $key_9567 = { c1 0f [2] b5 17 [2] f2 15 [2] b5 04 [2] fb 08 [2] f7 02 [2] e0 09 [2] fb 47 [2] c6 }

  condition:
    any of them
}
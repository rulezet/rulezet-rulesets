rule TTP_XOR_MULT_DOSStub_9067 {
  strings:
    $key_9067 = { c4 0f [2] b0 17 [2] f7 15 [2] b0 04 [2] fe 08 [2] f2 02 [2] e5 09 [2] fe 47 [2] c3 }

  condition:
    any of them
}
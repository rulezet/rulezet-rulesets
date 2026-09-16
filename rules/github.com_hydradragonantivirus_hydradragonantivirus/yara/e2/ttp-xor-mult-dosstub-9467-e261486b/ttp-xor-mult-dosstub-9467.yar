rule TTP_XOR_MULT_DOSStub_9467 {
  strings:
    $key_9467 = { c0 0f [2] b4 17 [2] f3 15 [2] b4 04 [2] fa 08 [2] f6 02 [2] e1 09 [2] fa 47 [2] c7 }

  condition:
    any of them
}
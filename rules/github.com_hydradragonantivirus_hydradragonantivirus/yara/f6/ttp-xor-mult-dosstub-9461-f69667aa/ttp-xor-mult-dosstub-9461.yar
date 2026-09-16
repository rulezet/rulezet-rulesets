rule TTP_XOR_MULT_DOSStub_9461 {
  strings:
    $key_9461 = { c0 09 [2] b4 11 [2] f3 13 [2] b4 02 [2] fa 0e [2] f6 04 [2] e1 0f [2] fa 41 [2] c7 }

  condition:
    any of them
}
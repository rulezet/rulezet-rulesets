rule TTP_XOR_MULT_DOSStub_9420 {
  strings:
    $key_9420 = { c0 48 [2] b4 50 [2] f3 52 [2] b4 43 [2] fa 4f [2] f6 45 [2] e1 4e [2] fa 00 [2] c7 }

  condition:
    any of them
}
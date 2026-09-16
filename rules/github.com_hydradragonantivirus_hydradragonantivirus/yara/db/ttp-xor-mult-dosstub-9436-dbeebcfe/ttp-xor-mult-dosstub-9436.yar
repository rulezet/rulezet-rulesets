rule TTP_XOR_MULT_DOSStub_9436 {
  strings:
    $key_9436 = { c0 5e [2] b4 46 [2] f3 44 [2] b4 55 [2] fa 59 [2] f6 53 [2] e1 58 [2] fa 16 [2] c7 }

  condition:
    any of them
}
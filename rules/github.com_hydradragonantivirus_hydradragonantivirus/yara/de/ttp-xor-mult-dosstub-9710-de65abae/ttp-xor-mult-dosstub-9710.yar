rule TTP_XOR_MULT_DOSStub_9710 {
  strings:
    $key_9710 = { c3 78 [2] b7 60 [2] f0 62 [2] b7 73 [2] f9 7f [2] f5 75 [2] e2 7e [2] f9 30 [2] c4 }

  condition:
    any of them
}
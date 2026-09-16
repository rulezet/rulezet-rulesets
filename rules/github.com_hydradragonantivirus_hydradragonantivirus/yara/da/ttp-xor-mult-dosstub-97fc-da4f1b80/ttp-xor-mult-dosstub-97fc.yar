rule TTP_XOR_MULT_DOSStub_97fc {
  strings:
    $key_97fc = { c3 94 [2] b7 8c [2] f0 8e [2] b7 9f [2] f9 93 [2] f5 99 [2] e2 92 [2] f9 dc [2] c4 }

  condition:
    any of them
}
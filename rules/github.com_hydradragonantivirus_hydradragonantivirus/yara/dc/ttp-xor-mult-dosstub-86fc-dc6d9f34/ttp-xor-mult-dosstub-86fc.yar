rule TTP_XOR_MULT_DOSStub_86fc {
  strings:
    $key_86fc = { d2 94 [2] a6 8c [2] e1 8e [2] a6 9f [2] e8 93 [2] e4 99 [2] f3 92 [2] e8 dc [2] d5 }

  condition:
    any of them
}
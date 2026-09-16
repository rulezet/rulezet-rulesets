rule TTP_XOR_MULT_DOSStub_9711 {
  strings:
    $key_9711 = { c3 79 [2] b7 61 [2] f0 63 [2] b7 72 [2] f9 7e [2] f5 74 [2] e2 7f [2] f9 31 [2] c4 }

  condition:
    any of them
}
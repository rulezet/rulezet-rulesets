rule TTP_XOR_MULT_DOSStub_9030 {
  strings:
    $key_9030 = { c4 58 [2] b0 40 [2] f7 42 [2] b0 53 [2] fe 5f [2] f2 55 [2] e5 5e [2] fe 10 [2] c3 }

  condition:
    any of them
}
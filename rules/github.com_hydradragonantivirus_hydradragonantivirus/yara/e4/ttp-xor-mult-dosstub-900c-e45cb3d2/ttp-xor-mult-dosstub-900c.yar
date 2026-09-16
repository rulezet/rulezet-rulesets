rule TTP_XOR_MULT_DOSStub_900c {
  strings:
    $key_900c = { c4 64 [2] b0 7c [2] f7 7e [2] b0 6f [2] fe 63 [2] f2 69 [2] e5 62 [2] fe 2c [2] c3 }

  condition:
    any of them
}
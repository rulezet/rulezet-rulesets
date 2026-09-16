rule TTP_XOR_MULT_DOSStub_9200 {
  strings:
    $key_9200 = { c6 68 [2] b2 70 [2] f5 72 [2] b2 63 [2] fc 6f [2] f0 65 [2] e7 6e [2] fc 20 [2] c1 }

  condition:
    any of them
}
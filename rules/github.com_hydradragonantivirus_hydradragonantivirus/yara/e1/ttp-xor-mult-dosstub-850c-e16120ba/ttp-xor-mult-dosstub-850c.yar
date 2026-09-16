rule TTP_XOR_MULT_DOSStub_850c {
  strings:
    $key_850c = { d1 64 [2] a5 7c [2] e2 7e [2] a5 6f [2] eb 63 [2] e7 69 [2] f0 62 [2] eb 2c [2] d6 }

  condition:
    any of them
}
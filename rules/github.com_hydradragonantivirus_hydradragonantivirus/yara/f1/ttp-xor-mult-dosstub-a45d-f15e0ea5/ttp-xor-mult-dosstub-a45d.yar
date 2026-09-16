rule TTP_XOR_MULT_DOSStub_a45d {
  strings:
    $key_a45d = { f0 35 [2] 84 2d [2] c3 2f [2] 84 3e [2] ca 32 [2] c6 38 [2] d1 33 [2] ca 7d [2] f7 }

  condition:
    any of them
}
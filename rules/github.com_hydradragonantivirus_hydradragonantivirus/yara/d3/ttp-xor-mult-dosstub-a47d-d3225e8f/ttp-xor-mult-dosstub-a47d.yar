rule TTP_XOR_MULT_DOSStub_a47d {
  strings:
    $key_a47d = { f0 15 [2] 84 0d [2] c3 0f [2] 84 1e [2] ca 12 [2] c6 18 [2] d1 13 [2] ca 5d [2] f7 }

  condition:
    any of them
}
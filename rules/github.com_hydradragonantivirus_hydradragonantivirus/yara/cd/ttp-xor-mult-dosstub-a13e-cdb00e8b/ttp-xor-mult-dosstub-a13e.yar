rule TTP_XOR_MULT_DOSStub_a13e {
  strings:
    $key_a13e = { f5 56 [2] 81 4e [2] c6 4c [2] 81 5d [2] cf 51 [2] c3 5b [2] d4 50 [2] cf 1e [2] f2 }

  condition:
    any of them
}
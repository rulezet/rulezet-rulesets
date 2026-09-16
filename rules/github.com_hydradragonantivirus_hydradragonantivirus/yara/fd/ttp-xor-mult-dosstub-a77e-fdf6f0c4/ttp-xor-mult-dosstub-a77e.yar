rule TTP_XOR_MULT_DOSStub_a77e {
  strings:
    $key_a77e = { f3 16 [2] 87 0e [2] c0 0c [2] 87 1d [2] c9 11 [2] c5 1b [2] d2 10 [2] c9 5e [2] f4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_a11e {
  strings:
    $key_a11e = { f5 76 [2] 81 6e [2] c6 6c [2] 81 7d [2] cf 71 [2] c3 7b [2] d4 70 [2] cf 3e [2] f2 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_a61e {
  strings:
    $key_a61e = { f2 76 [2] 86 6e [2] c1 6c [2] 86 7d [2] c8 71 [2] c4 7b [2] d3 70 [2] c8 3e [2] f5 }

  condition:
    any of them
}
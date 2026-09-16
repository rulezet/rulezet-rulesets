rule TTP_XOR_MULT_DOSStub_a64c {
  strings:
    $key_a64c = { f2 24 [2] 86 3c [2] c1 3e [2] 86 2f [2] c8 23 [2] c4 29 [2] d3 22 [2] c8 6c [2] f5 }

  condition:
    any of them
}
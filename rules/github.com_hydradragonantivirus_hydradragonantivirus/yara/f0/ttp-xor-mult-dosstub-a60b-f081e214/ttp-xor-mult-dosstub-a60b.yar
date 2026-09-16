rule TTP_XOR_MULT_DOSStub_a60b {
  strings:
    $key_a60b = { f2 63 [2] 86 7b [2] c1 79 [2] 86 68 [2] c8 64 [2] c4 6e [2] d3 65 [2] c8 2b [2] f5 }

  condition:
    any of them
}
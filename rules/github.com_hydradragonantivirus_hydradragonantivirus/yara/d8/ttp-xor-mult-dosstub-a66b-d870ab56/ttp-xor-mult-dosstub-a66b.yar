rule TTP_XOR_MULT_DOSStub_a66b {
  strings:
    $key_a66b = { f2 03 [2] 86 1b [2] c1 19 [2] 86 08 [2] c8 04 [2] c4 0e [2] d3 05 [2] c8 4b [2] f5 }

  condition:
    any of them
}
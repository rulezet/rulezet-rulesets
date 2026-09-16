rule TTP_XOR_MULT_DOSStub_a16b {
  strings:
    $key_a16b = { f5 03 [2] 81 1b [2] c6 19 [2] 81 08 [2] cf 04 [2] c3 0e [2] d4 05 [2] cf 4b [2] f2 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_eea7 {
  strings:
    $key_eea7 = { ba cf [2] ce d7 [2] 89 d5 [2] ce c4 [2] 80 c8 [2] 8c c2 [2] 9b c9 [2] 80 87 [2] bd }

  condition:
    any of them
}
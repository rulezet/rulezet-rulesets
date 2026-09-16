rule TTP_XOR_MULT_DOSStub_2ea3 {
  strings:
    $key_2ea3 = { 7a cb [2] 0e d3 [2] 49 d1 [2] 0e c0 [2] 40 cc [2] 4c c6 [2] 5b cd [2] 40 83 [2] 7d }

  condition:
    any of them
}
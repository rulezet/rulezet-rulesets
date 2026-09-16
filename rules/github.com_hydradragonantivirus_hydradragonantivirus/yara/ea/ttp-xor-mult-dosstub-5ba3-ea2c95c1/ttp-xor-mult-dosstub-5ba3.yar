rule TTP_XOR_MULT_DOSStub_5ba3 {
  strings:
    $key_5ba3 = { 0f cb [2] 7b d3 [2] 3c d1 [2] 7b c0 [2] 35 cc [2] 39 c6 [2] 2e cd [2] 35 83 [2] 08 }

  condition:
    any of them
}
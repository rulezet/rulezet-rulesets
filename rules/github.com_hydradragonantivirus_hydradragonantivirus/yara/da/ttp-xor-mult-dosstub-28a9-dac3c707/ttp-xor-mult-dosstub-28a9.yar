rule TTP_XOR_MULT_DOSStub_28a9 {
  strings:
    $key_28a9 = { 7c c1 [2] 08 d9 [2] 4f db [2] 08 ca [2] 46 c6 [2] 4a cc [2] 5d c7 [2] 46 89 [2] 7b }

  condition:
    any of them
}
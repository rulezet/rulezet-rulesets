rule TTP_XOR_MULT_DOSStub_1ca3 {
  strings:
    $key_1ca3 = { 48 cb [2] 3c d3 [2] 7b d1 [2] 3c c0 [2] 72 cc [2] 7e c6 [2] 69 cd [2] 72 83 [2] 4f }

  condition:
    any of them
}
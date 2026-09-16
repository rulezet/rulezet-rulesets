rule TTP_XOR_MULT_DOSStub_7ca2 {
  strings:
    $key_7ca2 = { 28 ca [2] 5c d2 [2] 1b d0 [2] 5c c1 [2] 12 cd [2] 1e c7 [2] 09 cc [2] 12 82 [2] 2f }

  condition:
    any of them
}
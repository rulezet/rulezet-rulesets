rule TTP_XOR_MULT_DOSStub_4ca2 {
  strings:
    $key_4ca2 = { 18 ca [2] 6c d2 [2] 2b d0 [2] 6c c1 [2] 22 cd [2] 2e c7 [2] 39 cc [2] 22 82 [2] 1f }

  condition:
    any of them
}
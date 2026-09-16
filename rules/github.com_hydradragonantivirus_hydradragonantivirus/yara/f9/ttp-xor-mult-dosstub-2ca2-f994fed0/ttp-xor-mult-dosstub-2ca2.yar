rule TTP_XOR_MULT_DOSStub_2ca2 {
  strings:
    $key_2ca2 = { 78 ca [2] 0c d2 [2] 4b d0 [2] 0c c1 [2] 42 cd [2] 4e c7 [2] 59 cc [2] 42 82 [2] 7f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4da2 {
  strings:
    $key_4da2 = { 19 ca [2] 6d d2 [2] 2a d0 [2] 6d c1 [2] 23 cd [2] 2f c7 [2] 38 cc [2] 23 82 [2] 1e }

  condition:
    any of them
}
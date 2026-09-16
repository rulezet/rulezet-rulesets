rule TTP_XOR_MULT_DOSStub_50a2 {
  strings:
    $key_50a2 = { 04 ca [2] 70 d2 [2] 37 d0 [2] 70 c1 [2] 3e cd [2] 32 c7 [2] 25 cc [2] 3e 82 [2] 03 }

  condition:
    any of them
}
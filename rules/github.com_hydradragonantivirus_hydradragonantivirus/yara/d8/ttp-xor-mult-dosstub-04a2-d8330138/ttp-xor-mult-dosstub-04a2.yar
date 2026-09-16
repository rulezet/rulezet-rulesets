rule TTP_XOR_MULT_DOSStub_04a2 {
  strings:
    $key_04a2 = { 50 ca [2] 24 d2 [2] 63 d0 [2] 24 c1 [2] 6a cd [2] 66 c7 [2] 71 cc [2] 6a 82 [2] 57 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_21a2 {
  strings:
    $key_21a2 = { 75 ca [2] 01 d2 [2] 46 d0 [2] 01 c1 [2] 4f cd [2] 43 c7 [2] 54 cc [2] 4f 82 [2] 72 }

  condition:
    any of them
}
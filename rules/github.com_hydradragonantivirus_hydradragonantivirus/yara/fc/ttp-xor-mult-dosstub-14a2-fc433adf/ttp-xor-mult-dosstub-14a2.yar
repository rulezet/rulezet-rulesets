rule TTP_XOR_MULT_DOSStub_14a2 {
  strings:
    $key_14a2 = { 40 ca [2] 34 d2 [2] 73 d0 [2] 34 c1 [2] 7a cd [2] 76 c7 [2] 61 cc [2] 7a 82 [2] 47 }

  condition:
    any of them
}
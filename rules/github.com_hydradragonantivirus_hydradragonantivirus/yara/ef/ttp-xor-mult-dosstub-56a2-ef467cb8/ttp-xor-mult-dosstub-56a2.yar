rule TTP_XOR_MULT_DOSStub_56a2 {
  strings:
    $key_56a2 = { 02 ca [2] 76 d2 [2] 31 d0 [2] 76 c1 [2] 38 cd [2] 34 c7 [2] 23 cc [2] 38 82 [2] 05 }

  condition:
    any of them
}
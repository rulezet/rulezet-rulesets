rule TTP_XOR_MULT_DOSStub_25a2 {
  strings:
    $key_25a2 = { 71 ca [2] 05 d2 [2] 42 d0 [2] 05 c1 [2] 4b cd [2] 47 c7 [2] 50 cc [2] 4b 82 [2] 76 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_43a2 {
  strings:
    $key_43a2 = { 17 ca [2] 63 d2 [2] 24 d0 [2] 63 c1 [2] 2d cd [2] 21 c7 [2] 36 cc [2] 2d 82 [2] 10 }

  condition:
    any of them
}
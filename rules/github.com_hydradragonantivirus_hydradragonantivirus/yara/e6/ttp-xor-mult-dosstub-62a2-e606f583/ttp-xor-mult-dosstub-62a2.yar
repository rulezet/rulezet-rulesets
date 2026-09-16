rule TTP_XOR_MULT_DOSStub_62a2 {
  strings:
    $key_62a2 = { 36 ca [2] 42 d2 [2] 05 d0 [2] 42 c1 [2] 0c cd [2] 00 c7 [2] 17 cc [2] 0c 82 [2] 31 }

  condition:
    any of them
}
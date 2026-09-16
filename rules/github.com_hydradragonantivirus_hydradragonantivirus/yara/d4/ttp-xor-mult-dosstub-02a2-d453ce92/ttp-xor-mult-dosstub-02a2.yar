rule TTP_XOR_MULT_DOSStub_02a2 {
  strings:
    $key_02a2 = { 56 ca [2] 22 d2 [2] 65 d0 [2] 22 c1 [2] 6c cd [2] 60 c7 [2] 77 cc [2] 6c 82 [2] 51 }

  condition:
    any of them
}
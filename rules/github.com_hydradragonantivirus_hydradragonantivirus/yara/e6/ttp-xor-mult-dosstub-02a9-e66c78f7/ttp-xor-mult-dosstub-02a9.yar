rule TTP_XOR_MULT_DOSStub_02a9 {
  strings:
    $key_02a9 = { 56 c1 [2] 22 d9 [2] 65 db [2] 22 ca [2] 6c c6 [2] 60 cc [2] 77 c7 [2] 6c 89 [2] 51 }

  condition:
    any of them
}
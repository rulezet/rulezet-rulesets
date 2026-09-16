rule TTP_XOR_MULT_DOSStub_24a9 {
  strings:
    $key_24a9 = { 70 c1 [2] 04 d9 [2] 43 db [2] 04 ca [2] 4a c6 [2] 46 cc [2] 51 c7 [2] 4a 89 [2] 77 }

  condition:
    any of them
}
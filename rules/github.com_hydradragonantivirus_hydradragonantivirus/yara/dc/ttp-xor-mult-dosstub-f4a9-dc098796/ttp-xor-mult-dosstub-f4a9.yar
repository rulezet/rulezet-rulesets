rule TTP_XOR_MULT_DOSStub_f4a9 {
  strings:
    $key_f4a9 = { a0 c1 [2] d4 d9 [2] 93 db [2] d4 ca [2] 9a c6 [2] 96 cc [2] 81 c7 [2] 9a 89 [2] a7 }

  condition:
    any of them
}
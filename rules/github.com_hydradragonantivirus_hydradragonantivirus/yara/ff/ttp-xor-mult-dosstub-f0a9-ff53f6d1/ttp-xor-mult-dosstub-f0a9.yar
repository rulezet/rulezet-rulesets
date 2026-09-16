rule TTP_XOR_MULT_DOSStub_f0a9 {
  strings:
    $key_f0a9 = { a4 c1 [2] d0 d9 [2] 97 db [2] d0 ca [2] 9e c6 [2] 92 cc [2] 85 c7 [2] 9e 89 [2] a3 }

  condition:
    any of them
}
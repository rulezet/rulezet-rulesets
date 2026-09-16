rule TTP_XOR_MULT_DOSStub_5fa9 {
  strings:
    $key_5fa9 = { 0b c1 [2] 7f d9 [2] 38 db [2] 7f ca [2] 31 c6 [2] 3d cc [2] 2a c7 [2] 31 89 [2] 0c }

  condition:
    any of them
}
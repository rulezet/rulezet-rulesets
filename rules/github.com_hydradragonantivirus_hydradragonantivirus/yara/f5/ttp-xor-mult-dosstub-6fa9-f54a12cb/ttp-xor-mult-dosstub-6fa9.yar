rule TTP_XOR_MULT_DOSStub_6fa9 {
  strings:
    $key_6fa9 = { 3b c1 [2] 4f d9 [2] 08 db [2] 4f ca [2] 01 c6 [2] 0d cc [2] 1a c7 [2] 01 89 [2] 3c }

  condition:
    any of them
}
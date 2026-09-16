rule TTP_XOR_MULT_DOSStub_6fa8 {
  strings:
    $key_6fa8 = { 3b c0 [2] 4f d8 [2] 08 da [2] 4f cb [2] 01 c7 [2] 0d cd [2] 1a c6 [2] 01 88 [2] 3c }

  condition:
    any of them
}
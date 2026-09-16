rule TTP_XOR_MULT_DOSStub_6f31 {
  strings:
    $key_6f31 = { 3b 59 [2] 4f 41 [2] 08 43 [2] 4f 52 [2] 01 5e [2] 0d 54 [2] 1a 5f [2] 01 11 [2] 3c }

  condition:
    any of them
}
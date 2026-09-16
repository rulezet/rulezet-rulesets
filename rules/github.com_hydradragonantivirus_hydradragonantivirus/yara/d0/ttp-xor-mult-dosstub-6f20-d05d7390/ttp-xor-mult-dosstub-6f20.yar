rule TTP_XOR_MULT_DOSStub_6f20 {
  strings:
    $key_6f20 = { 3b 48 [2] 4f 50 [2] 08 52 [2] 4f 43 [2] 01 4f [2] 0d 45 [2] 1a 4e [2] 01 00 [2] 3c }

  condition:
    any of them
}
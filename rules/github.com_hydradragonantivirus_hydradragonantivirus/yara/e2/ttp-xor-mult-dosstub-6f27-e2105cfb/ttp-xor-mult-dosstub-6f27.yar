rule TTP_XOR_MULT_DOSStub_6f27 {
  strings:
    $key_6f27 = { 3b 4f [2] 4f 57 [2] 08 55 [2] 4f 44 [2] 01 48 [2] 0d 42 [2] 1a 49 [2] 01 07 [2] 3c }

  condition:
    any of them
}
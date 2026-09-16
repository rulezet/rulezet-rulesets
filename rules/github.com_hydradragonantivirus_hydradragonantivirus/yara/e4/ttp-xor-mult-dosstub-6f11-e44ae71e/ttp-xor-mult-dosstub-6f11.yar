rule TTP_XOR_MULT_DOSStub_6f11 {
  strings:
    $key_6f11 = { 3b 79 [2] 4f 61 [2] 08 63 [2] 4f 72 [2] 01 7e [2] 0d 74 [2] 1a 7f [2] 01 31 [2] 3c }

  condition:
    any of them
}
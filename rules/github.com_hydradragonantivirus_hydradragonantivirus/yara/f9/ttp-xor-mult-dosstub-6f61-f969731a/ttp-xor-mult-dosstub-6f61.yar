rule TTP_XOR_MULT_DOSStub_6f61 {
  strings:
    $key_6f61 = { 3b 09 [2] 4f 11 [2] 08 13 [2] 4f 02 [2] 01 0e [2] 0d 04 [2] 1a 0f [2] 01 41 [2] 3c }

  condition:
    any of them
}
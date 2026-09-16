rule TTP_XOR_MULT_DOSStub_6f68 {
  strings:
    $key_6f68 = { 3b 00 [2] 4f 18 [2] 08 1a [2] 4f 0b [2] 01 07 [2] 0d 0d [2] 1a 06 [2] 01 48 [2] 3c }

  condition:
    any of them
}
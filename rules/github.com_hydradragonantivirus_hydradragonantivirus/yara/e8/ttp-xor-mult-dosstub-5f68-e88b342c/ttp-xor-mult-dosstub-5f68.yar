rule TTP_XOR_MULT_DOSStub_5f68 {
  strings:
    $key_5f68 = { 0b 00 [2] 7f 18 [2] 38 1a [2] 7f 0b [2] 31 07 [2] 3d 0d [2] 2a 06 [2] 31 48 [2] 0c }

  condition:
    any of them
}
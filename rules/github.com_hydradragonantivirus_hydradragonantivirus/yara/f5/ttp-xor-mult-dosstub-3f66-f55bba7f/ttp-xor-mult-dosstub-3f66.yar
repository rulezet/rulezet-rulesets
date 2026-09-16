rule TTP_XOR_MULT_DOSStub_3f66 {
  strings:
    $key_3f66 = { 6b 0e [2] 1f 16 [2] 58 14 [2] 1f 05 [2] 51 09 [2] 5d 03 [2] 4a 08 [2] 51 46 [2] 6c }

  condition:
    any of them
}
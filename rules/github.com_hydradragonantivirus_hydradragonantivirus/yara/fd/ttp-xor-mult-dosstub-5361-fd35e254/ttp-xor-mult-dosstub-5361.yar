rule TTP_XOR_MULT_DOSStub_5361 {
  strings:
    $key_5361 = { 07 09 [2] 73 11 [2] 34 13 [2] 73 02 [2] 3d 0e [2] 31 04 [2] 26 0f [2] 3d 41 [2] 00 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5371 {
  strings:
    $key_5371 = { 07 19 [2] 73 01 [2] 34 03 [2] 73 12 [2] 3d 1e [2] 31 14 [2] 26 1f [2] 3d 51 [2] 00 }

  condition:
    any of them
}
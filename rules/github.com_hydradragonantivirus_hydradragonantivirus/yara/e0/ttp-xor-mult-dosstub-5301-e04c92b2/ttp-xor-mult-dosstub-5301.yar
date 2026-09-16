rule TTP_XOR_MULT_DOSStub_5301 {
  strings:
    $key_5301 = { 07 69 [2] 73 71 [2] 34 73 [2] 73 62 [2] 3d 6e [2] 31 64 [2] 26 6f [2] 3d 21 [2] 00 }

  condition:
    any of them
}
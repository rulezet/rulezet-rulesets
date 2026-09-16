rule TTP_XOR_MULT_DOSStub_53f6 {
  strings:
    $key_53f6 = { 07 9e [2] 73 86 [2] 34 84 [2] 73 95 [2] 3d 99 [2] 31 93 [2] 26 98 [2] 3d d6 [2] 00 }

  condition:
    any of them
}
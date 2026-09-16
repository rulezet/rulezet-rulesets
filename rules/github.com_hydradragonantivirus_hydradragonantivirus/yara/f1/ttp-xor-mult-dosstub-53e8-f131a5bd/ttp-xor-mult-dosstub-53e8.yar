rule TTP_XOR_MULT_DOSStub_53e8 {
  strings:
    $key_53e8 = { 07 80 [2] 73 98 [2] 34 9a [2] 73 8b [2] 3d 87 [2] 31 8d [2] 26 86 [2] 3d c8 [2] 00 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_53e5 {
  strings:
    $key_53e5 = { 07 8d [2] 73 95 [2] 34 97 [2] 73 86 [2] 3d 8a [2] 31 80 [2] 26 8b [2] 3d c5 [2] 00 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_53f4 {
  strings:
    $key_53f4 = { 07 9c [2] 73 84 [2] 34 86 [2] 73 97 [2] 3d 9b [2] 31 91 [2] 26 9a [2] 3d d4 [2] 00 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_531e {
  strings:
    $key_531e = { 07 76 [2] 73 6e [2] 34 6c [2] 73 7d [2] 3d 71 [2] 31 7b [2] 26 70 [2] 3d 3e [2] 00 }

  condition:
    any of them
}
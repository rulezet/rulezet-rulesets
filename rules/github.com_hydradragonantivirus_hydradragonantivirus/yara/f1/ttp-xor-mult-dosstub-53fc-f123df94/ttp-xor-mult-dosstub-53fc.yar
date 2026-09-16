rule TTP_XOR_MULT_DOSStub_53fc {
  strings:
    $key_53fc = { 07 94 [2] 73 8c [2] 34 8e [2] 73 9f [2] 3d 93 [2] 31 99 [2] 26 92 [2] 3d dc [2] 00 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_53fd {
  strings:
    $key_53fd = { 07 95 [2] 73 8d [2] 34 8f [2] 73 9e [2] 3d 92 [2] 31 98 [2] 26 93 [2] 3d dd [2] 00 }

  condition:
    any of them
}
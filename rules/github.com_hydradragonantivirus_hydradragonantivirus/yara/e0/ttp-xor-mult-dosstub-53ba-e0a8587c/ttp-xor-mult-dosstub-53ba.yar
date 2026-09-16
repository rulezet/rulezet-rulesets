rule TTP_XOR_MULT_DOSStub_53ba {
  strings:
    $key_53ba = { 07 d2 [2] 73 ca [2] 34 c8 [2] 73 d9 [2] 3d d5 [2] 31 df [2] 26 d4 [2] 3d 9a [2] 00 }

  condition:
    any of them
}
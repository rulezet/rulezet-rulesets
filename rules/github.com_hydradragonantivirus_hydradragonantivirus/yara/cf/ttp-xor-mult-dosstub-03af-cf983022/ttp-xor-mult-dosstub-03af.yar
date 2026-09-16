rule TTP_XOR_MULT_DOSStub_03af {
  strings:
    $key_03af = { 57 c7 [2] 23 df [2] 64 dd [2] 23 cc [2] 6d c0 [2] 61 ca [2] 76 c1 [2] 6d 8f [2] 50 }

  condition:
    any of them
}
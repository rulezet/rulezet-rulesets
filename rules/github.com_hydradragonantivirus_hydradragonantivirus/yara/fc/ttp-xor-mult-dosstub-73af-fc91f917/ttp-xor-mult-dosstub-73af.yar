rule TTP_XOR_MULT_DOSStub_73af {
  strings:
    $key_73af = { 27 c7 [2] 53 df [2] 14 dd [2] 53 cc [2] 1d c0 [2] 11 ca [2] 06 c1 [2] 1d 8f [2] 20 }

  condition:
    any of them
}
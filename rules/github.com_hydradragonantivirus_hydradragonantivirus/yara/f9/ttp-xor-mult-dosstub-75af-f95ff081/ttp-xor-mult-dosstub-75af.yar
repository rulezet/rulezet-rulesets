rule TTP_XOR_MULT_DOSStub_75af {
  strings:
    $key_75af = { 21 c7 [2] 55 df [2] 12 dd [2] 55 cc [2] 1b c0 [2] 17 ca [2] 00 c1 [2] 1b 8f [2] 26 }

  condition:
    any of them
}
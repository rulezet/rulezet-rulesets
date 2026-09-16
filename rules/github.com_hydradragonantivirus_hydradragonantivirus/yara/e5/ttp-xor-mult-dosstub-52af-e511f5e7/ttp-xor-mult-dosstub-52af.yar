rule TTP_XOR_MULT_DOSStub_52af {
  strings:
    $key_52af = { 06 c7 [2] 72 df [2] 35 dd [2] 72 cc [2] 3c c0 [2] 30 ca [2] 27 c1 [2] 3c 8f [2] 01 }

  condition:
    any of them
}
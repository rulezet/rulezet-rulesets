rule TTP_XOR_MULT_DOSStub_22af {
  strings:
    $key_22af = { 76 c7 [2] 02 df [2] 45 dd [2] 02 cc [2] 4c c0 [2] 40 ca [2] 57 c1 [2] 4c 8f [2] 71 }

  condition:
    any of them
}
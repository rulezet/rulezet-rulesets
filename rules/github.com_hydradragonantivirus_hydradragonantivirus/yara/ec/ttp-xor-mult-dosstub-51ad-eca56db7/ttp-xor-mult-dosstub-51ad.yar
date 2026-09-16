rule TTP_XOR_MULT_DOSStub_51ad {
  strings:
    $key_51ad = { 05 c5 [2] 71 dd [2] 36 df [2] 71 ce [2] 3f c2 [2] 33 c8 [2] 24 c3 [2] 3f 8d [2] 02 }

  condition:
    any of them
}
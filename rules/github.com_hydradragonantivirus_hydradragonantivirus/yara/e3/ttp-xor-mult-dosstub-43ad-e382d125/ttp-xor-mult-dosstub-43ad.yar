rule TTP_XOR_MULT_DOSStub_43ad {
  strings:
    $key_43ad = { 17 c5 [2] 63 dd [2] 24 df [2] 63 ce [2] 2d c2 [2] 21 c8 [2] 36 c3 [2] 2d 8d [2] 10 }

  condition:
    any of them
}
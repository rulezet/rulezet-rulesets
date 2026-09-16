rule TTP_XOR_MULT_DOSStub_e3ad {
  strings:
    $key_e3ad = { b7 c5 [2] c3 dd [2] 84 df [2] c3 ce [2] 8d c2 [2] 81 c8 [2] 96 c3 [2] 8d 8d [2] b0 }

  condition:
    any of them
}
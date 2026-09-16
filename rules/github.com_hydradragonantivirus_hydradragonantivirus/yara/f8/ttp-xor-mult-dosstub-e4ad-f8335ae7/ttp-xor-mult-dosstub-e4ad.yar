rule TTP_XOR_MULT_DOSStub_e4ad {
  strings:
    $key_e4ad = { b0 c5 [2] c4 dd [2] 83 df [2] c4 ce [2] 8a c2 [2] 86 c8 [2] 91 c3 [2] 8a 8d [2] b7 }

  condition:
    any of them
}
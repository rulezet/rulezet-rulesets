rule TTP_XOR_MULT_DOSStub_44ad {
  strings:
    $key_44ad = { 10 c5 [2] 64 dd [2] 23 df [2] 64 ce [2] 2a c2 [2] 26 c8 [2] 31 c3 [2] 2a 8d [2] 17 }

  condition:
    any of them
}
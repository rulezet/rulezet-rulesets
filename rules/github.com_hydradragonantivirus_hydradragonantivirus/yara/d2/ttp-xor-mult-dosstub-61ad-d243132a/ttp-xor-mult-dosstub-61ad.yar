rule TTP_XOR_MULT_DOSStub_61ad {
  strings:
    $key_61ad = { 35 c5 [2] 41 dd [2] 06 df [2] 41 ce [2] 0f c2 [2] 03 c8 [2] 14 c3 [2] 0f 8d [2] 32 }

  condition:
    any of them
}
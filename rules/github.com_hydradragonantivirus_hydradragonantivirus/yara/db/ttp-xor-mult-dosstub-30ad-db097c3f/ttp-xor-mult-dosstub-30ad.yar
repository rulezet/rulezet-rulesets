rule TTP_XOR_MULT_DOSStub_30ad {
  strings:
    $key_30ad = { 64 c5 [2] 10 dd [2] 57 df [2] 10 ce [2] 5e c2 [2] 52 c8 [2] 45 c3 [2] 5e 8d [2] 63 }

  condition:
    any of them
}
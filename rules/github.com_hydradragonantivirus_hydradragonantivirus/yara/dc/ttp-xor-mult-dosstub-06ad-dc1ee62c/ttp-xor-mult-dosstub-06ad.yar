rule TTP_XOR_MULT_DOSStub_06ad {
  strings:
    $key_06ad = { 52 c5 [2] 26 dd [2] 61 df [2] 26 ce [2] 68 c2 [2] 64 c8 [2] 73 c3 [2] 68 8d [2] 55 }

  condition:
    any of them
}
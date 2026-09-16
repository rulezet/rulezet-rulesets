rule TTP_XOR_MULT_DOSStub_88ad {
  strings:
    $key_88ad = { dc c5 [2] a8 dd [2] ef df [2] a8 ce [2] e6 c2 [2] ea c8 [2] fd c3 [2] e6 8d [2] db }

  condition:
    any of them
}
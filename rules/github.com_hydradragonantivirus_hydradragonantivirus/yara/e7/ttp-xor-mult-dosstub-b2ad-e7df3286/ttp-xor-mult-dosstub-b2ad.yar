rule TTP_XOR_MULT_DOSStub_b2ad {
  strings:
    $key_b2ad = { e6 c5 [2] 92 dd [2] d5 df [2] 92 ce [2] dc c2 [2] d0 c8 [2] c7 c3 [2] dc 8d [2] e1 }

  condition:
    any of them
}
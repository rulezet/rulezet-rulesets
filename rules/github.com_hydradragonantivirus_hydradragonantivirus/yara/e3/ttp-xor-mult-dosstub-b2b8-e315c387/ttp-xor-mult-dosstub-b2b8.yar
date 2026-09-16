rule TTP_XOR_MULT_DOSStub_b2b8 {
  strings:
    $key_b2b8 = { e6 d0 [2] 92 c8 [2] d5 ca [2] 92 db [2] dc d7 [2] d0 dd [2] c7 d6 [2] dc 98 [2] e1 }

  condition:
    any of them
}
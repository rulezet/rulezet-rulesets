rule TTP_XOR_MULT_DOSStub_82ad {
  strings:
    $key_82ad = { d6 c5 [2] a2 dd [2] e5 df [2] a2 ce [2] ec c2 [2] e0 c8 [2] f7 c3 [2] ec 8d [2] d1 }

  condition:
    any of them
}
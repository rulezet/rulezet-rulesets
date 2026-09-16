rule TTP_XOR_MULT_DOSStub_eab2 {
  strings:
    $key_eab2 = { be da [2] ca c2 [2] 8d c0 [2] ca d1 [2] 84 dd [2] 88 d7 [2] 9f dc [2] 84 92 [2] b9 }

  condition:
    any of them
}
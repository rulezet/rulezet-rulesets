rule TTP_XOR_MULT_DOSStub_e9b2 {
  strings:
    $key_e9b2 = { bd da [2] c9 c2 [2] 8e c0 [2] c9 d1 [2] 87 dd [2] 8b d7 [2] 9c dc [2] 87 92 [2] ba }

  condition:
    any of them
}
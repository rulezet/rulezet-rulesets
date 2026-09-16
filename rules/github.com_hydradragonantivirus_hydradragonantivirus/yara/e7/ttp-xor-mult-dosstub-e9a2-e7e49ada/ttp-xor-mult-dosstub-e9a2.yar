rule TTP_XOR_MULT_DOSStub_e9a2 {
  strings:
    $key_e9a2 = { bd ca [2] c9 d2 [2] 8e d0 [2] c9 c1 [2] 87 cd [2] 8b c7 [2] 9c cc [2] 87 82 [2] ba }

  condition:
    any of them
}
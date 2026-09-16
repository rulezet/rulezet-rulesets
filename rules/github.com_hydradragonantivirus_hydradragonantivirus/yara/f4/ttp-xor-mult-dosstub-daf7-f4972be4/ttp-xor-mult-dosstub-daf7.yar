rule TTP_XOR_MULT_DOSStub_daf7 {
  strings:
    $key_daf7 = { 8e 9f [2] fa 87 [2] bd 85 [2] fa 94 [2] b4 98 [2] b8 92 [2] af 99 [2] b4 d7 [2] 89 }

  condition:
    any of them
}
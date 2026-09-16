rule TTP_XOR_MULT_DOSStub_daf1 {
  strings:
    $key_daf1 = { 8e 99 [2] fa 81 [2] bd 83 [2] fa 92 [2] b4 9e [2] b8 94 [2] af 9f [2] b4 d1 [2] 89 }

  condition:
    any of them
}
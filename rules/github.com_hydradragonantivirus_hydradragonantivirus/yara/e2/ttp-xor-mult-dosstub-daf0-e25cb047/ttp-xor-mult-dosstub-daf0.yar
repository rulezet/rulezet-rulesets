rule TTP_XOR_MULT_DOSStub_daf0 {
  strings:
    $key_daf0 = { 8e 98 [2] fa 80 [2] bd 82 [2] fa 93 [2] b4 9f [2] b8 95 [2] af 9e [2] b4 d0 [2] 89 }

  condition:
    any of them
}
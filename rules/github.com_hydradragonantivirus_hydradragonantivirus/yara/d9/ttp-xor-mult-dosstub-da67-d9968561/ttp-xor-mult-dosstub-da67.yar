rule TTP_XOR_MULT_DOSStub_da67 {
  strings:
    $key_da67 = { 8e 0f [2] fa 17 [2] bd 15 [2] fa 04 [2] b4 08 [2] b8 02 [2] af 09 [2] b4 47 [2] 89 }

  condition:
    any of them
}
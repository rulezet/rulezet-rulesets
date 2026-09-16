rule TTP_XOR_MULT_DOSStub_da17 {
  strings:
    $key_da17 = { 8e 7f [2] fa 67 [2] bd 65 [2] fa 74 [2] b4 78 [2] b8 72 [2] af 79 [2] b4 37 [2] 89 }

  condition:
    any of them
}
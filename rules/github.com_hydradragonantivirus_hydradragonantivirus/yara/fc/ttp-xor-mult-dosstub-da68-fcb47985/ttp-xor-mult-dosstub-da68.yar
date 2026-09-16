rule TTP_XOR_MULT_DOSStub_da68 {
  strings:
    $key_da68 = { 8e 00 [2] fa 18 [2] bd 1a [2] fa 0b [2] b4 07 [2] b8 0d [2] af 06 [2] b4 48 [2] 89 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_da79 {
  strings:
    $key_da79 = { 8e 11 [2] fa 09 [2] bd 0b [2] fa 1a [2] b4 16 [2] b8 1c [2] af 17 [2] b4 59 [2] 89 }

  condition:
    any of them
}
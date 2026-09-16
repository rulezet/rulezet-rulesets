rule TTP_XOR_MULT_DOSStub_daf4 {
  strings:
    $key_daf4 = { 8e 9c [2] fa 84 [2] bd 86 [2] fa 97 [2] b4 9b [2] b8 91 [2] af 9a [2] b4 d4 [2] 89 }

  condition:
    any of them
}
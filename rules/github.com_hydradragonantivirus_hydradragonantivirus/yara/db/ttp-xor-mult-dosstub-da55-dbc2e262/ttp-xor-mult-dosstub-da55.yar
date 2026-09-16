rule TTP_XOR_MULT_DOSStub_da55 {
  strings:
    $key_da55 = { 8e 3d [2] fa 25 [2] bd 27 [2] fa 36 [2] b4 3a [2] b8 30 [2] af 3b [2] b4 75 [2] 89 }

  condition:
    any of them
}
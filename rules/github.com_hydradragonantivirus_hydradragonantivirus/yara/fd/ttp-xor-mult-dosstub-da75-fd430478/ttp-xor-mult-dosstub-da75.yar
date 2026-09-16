rule TTP_XOR_MULT_DOSStub_da75 {
  strings:
    $key_da75 = { 8e 1d [2] fa 05 [2] bd 07 [2] fa 16 [2] b4 1a [2] b8 10 [2] af 1b [2] b4 55 [2] 89 }

  condition:
    any of them
}
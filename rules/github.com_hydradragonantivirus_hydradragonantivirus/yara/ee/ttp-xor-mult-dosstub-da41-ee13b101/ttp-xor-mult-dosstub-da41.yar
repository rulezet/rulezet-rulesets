rule TTP_XOR_MULT_DOSStub_da41 {
  strings:
    $key_da41 = { 8e 29 [2] fa 31 [2] bd 33 [2] fa 22 [2] b4 2e [2] b8 24 [2] af 2f [2] b4 61 [2] 89 }

  condition:
    any of them
}
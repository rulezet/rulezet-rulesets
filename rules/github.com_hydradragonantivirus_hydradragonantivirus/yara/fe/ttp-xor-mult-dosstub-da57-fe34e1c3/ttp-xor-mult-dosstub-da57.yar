rule TTP_XOR_MULT_DOSStub_da57 {
  strings:
    $key_da57 = { 8e 3f [2] fa 27 [2] bd 25 [2] fa 34 [2] b4 38 [2] b8 32 [2] af 39 [2] b4 77 [2] 89 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_da07 {
  strings:
    $key_da07 = { 8e 6f [2] fa 77 [2] bd 75 [2] fa 64 [2] b4 68 [2] b8 62 [2] af 69 [2] b4 27 [2] 89 }

  condition:
    any of them
}
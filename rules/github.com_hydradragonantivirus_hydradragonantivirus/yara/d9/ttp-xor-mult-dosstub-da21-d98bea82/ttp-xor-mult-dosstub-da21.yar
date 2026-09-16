rule TTP_XOR_MULT_DOSStub_da21 {
  strings:
    $key_da21 = { 8e 49 [2] fa 51 [2] bd 53 [2] fa 42 [2] b4 4e [2] b8 44 [2] af 4f [2] b4 01 [2] 89 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_da0d {
  strings:
    $key_da0d = { 8e 65 [2] fa 7d [2] bd 7f [2] fa 6e [2] b4 62 [2] b8 68 [2] af 63 [2] b4 2d [2] 89 }

  condition:
    any of them
}
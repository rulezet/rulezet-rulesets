rule TTP_XOR_MULT_DOSStub_da4f {
  strings:
    $key_da4f = { 8e 27 [2] fa 3f [2] bd 3d [2] fa 2c [2] b4 20 [2] b8 2a [2] af 21 [2] b4 6f [2] 89 }

  condition:
    any of them
}
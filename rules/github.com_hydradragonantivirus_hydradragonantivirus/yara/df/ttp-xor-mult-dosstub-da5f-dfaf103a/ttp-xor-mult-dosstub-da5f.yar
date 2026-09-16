rule TTP_XOR_MULT_DOSStub_da5f {
  strings:
    $key_da5f = { 8e 37 [2] fa 2f [2] bd 2d [2] fa 3c [2] b4 30 [2] b8 3a [2] af 31 [2] b4 7f [2] 89 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_da1d {
  strings:
    $key_da1d = { 8e 75 [2] fa 6d [2] bd 6f [2] fa 7e [2] b4 72 [2] b8 78 [2] af 73 [2] b4 3d [2] 89 }

  condition:
    any of them
}
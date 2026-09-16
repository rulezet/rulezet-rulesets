rule TTP_XOR_MULT_DOSStub_da5e {
  strings:
    $key_da5e = { 8e 36 [2] fa 2e [2] bd 2c [2] fa 3d [2] b4 31 [2] b8 3b [2] af 30 [2] b4 7e [2] 89 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_da43 {
  strings:
    $key_da43 = { 8e 2b [2] fa 33 [2] bd 31 [2] fa 20 [2] b4 2c [2] b8 26 [2] af 2d [2] b4 63 [2] 89 }

  condition:
    any of them
}
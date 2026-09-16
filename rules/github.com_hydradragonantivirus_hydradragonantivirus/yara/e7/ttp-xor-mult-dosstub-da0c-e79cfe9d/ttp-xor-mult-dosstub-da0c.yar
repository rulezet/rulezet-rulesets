rule TTP_XOR_MULT_DOSStub_da0c {
  strings:
    $key_da0c = { 8e 64 [2] fa 7c [2] bd 7e [2] fa 6f [2] b4 63 [2] b8 69 [2] af 62 [2] b4 2c [2] 89 }

  condition:
    any of them
}
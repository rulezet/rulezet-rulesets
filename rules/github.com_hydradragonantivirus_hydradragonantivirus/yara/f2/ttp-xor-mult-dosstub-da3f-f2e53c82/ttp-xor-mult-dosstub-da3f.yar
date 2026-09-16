rule TTP_XOR_MULT_DOSStub_da3f {
  strings:
    $key_da3f = { 8e 57 [2] fa 4f [2] bd 4d [2] fa 5c [2] b4 50 [2] b8 5a [2] af 51 [2] b4 1f [2] 89 }

  condition:
    any of them
}
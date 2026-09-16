rule TTP_XOR_MULT_DOSStub_da38 {
  strings:
    $key_da38 = { 8e 50 [2] fa 48 [2] bd 4a [2] fa 5b [2] b4 57 [2] b8 5d [2] af 56 [2] b4 18 [2] 89 }

  condition:
    any of them
}
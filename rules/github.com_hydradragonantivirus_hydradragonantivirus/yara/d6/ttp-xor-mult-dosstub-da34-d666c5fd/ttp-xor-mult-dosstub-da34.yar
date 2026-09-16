rule TTP_XOR_MULT_DOSStub_da34 {
  strings:
    $key_da34 = { 8e 5c [2] fa 44 [2] bd 46 [2] fa 57 [2] b4 5b [2] b8 51 [2] af 5a [2] b4 14 [2] 89 }

  condition:
    any of them
}
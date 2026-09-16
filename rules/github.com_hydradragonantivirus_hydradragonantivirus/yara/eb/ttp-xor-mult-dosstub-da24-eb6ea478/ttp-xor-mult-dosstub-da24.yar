rule TTP_XOR_MULT_DOSStub_da24 {
  strings:
    $key_da24 = { 8e 4c [2] fa 54 [2] bd 56 [2] fa 47 [2] b4 4b [2] b8 41 [2] af 4a [2] b4 04 [2] 89 }

  condition:
    any of them
}
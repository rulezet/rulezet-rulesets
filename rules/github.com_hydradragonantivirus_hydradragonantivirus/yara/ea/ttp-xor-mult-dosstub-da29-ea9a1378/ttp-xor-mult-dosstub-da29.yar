rule TTP_XOR_MULT_DOSStub_da29 {
  strings:
    $key_da29 = { 8e 41 [2] fa 59 [2] bd 5b [2] fa 4a [2] b4 46 [2] b8 4c [2] af 47 [2] b4 09 [2] 89 }

  condition:
    any of them
}
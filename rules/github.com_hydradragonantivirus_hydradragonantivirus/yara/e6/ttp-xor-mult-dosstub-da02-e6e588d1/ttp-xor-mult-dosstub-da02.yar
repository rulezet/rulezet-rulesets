rule TTP_XOR_MULT_DOSStub_da02 {
  strings:
    $key_da02 = { 8e 6a [2] fa 72 [2] bd 70 [2] fa 61 [2] b4 6d [2] b8 67 [2] af 6c [2] b4 22 [2] 89 }

  condition:
    any of them
}
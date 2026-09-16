rule TTP_XOR_MULT_DOSStub_daf2 {
  strings:
    $key_daf2 = { 8e 9a [2] fa 82 [2] bd 80 [2] fa 91 [2] b4 9d [2] b8 97 [2] af 9c [2] b4 d2 [2] 89 }

  condition:
    any of them
}
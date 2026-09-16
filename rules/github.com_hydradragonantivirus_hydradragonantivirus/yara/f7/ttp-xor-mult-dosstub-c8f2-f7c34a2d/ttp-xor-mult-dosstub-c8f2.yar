rule TTP_XOR_MULT_DOSStub_c8f2 {
  strings:
    $key_c8f2 = { 9c 9a [2] e8 82 [2] af 80 [2] e8 91 [2] a6 9d [2] aa 97 [2] bd 9c [2] a6 d2 [2] 9b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c8e1 {
  strings:
    $key_c8e1 = { 9c 89 [2] e8 91 [2] af 93 [2] e8 82 [2] a6 8e [2] aa 84 [2] bd 8f [2] a6 c1 [2] 9b }

  condition:
    any of them
}
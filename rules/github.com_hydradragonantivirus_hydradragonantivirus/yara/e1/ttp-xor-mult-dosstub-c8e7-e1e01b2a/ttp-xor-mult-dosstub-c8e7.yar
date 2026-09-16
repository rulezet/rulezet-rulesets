rule TTP_XOR_MULT_DOSStub_c8e7 {
  strings:
    $key_c8e7 = { 9c 8f [2] e8 97 [2] af 95 [2] e8 84 [2] a6 88 [2] aa 82 [2] bd 89 [2] a6 c7 [2] 9b }

  condition:
    any of them
}
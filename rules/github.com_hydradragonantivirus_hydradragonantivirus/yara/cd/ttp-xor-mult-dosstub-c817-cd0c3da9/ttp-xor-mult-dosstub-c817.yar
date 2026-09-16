rule TTP_XOR_MULT_DOSStub_c817 {
  strings:
    $key_c817 = { 9c 7f [2] e8 67 [2] af 65 [2] e8 74 [2] a6 78 [2] aa 72 [2] bd 79 [2] a6 37 [2] 9b }

  condition:
    any of them
}
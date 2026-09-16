rule TTP_XOR_MULT_DOSStub_c820 {
  strings:
    $key_c820 = { 9c 48 [2] e8 50 [2] af 52 [2] e8 43 [2] a6 4f [2] aa 45 [2] bd 4e [2] a6 00 [2] 9b }

  condition:
    any of them
}
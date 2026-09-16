rule TTP_XOR_MULT_DOSStub_c837 {
  strings:
    $key_c837 = { 9c 5f [2] e8 47 [2] af 45 [2] e8 54 [2] a6 58 [2] aa 52 [2] bd 59 [2] a6 17 [2] 9b }

  condition:
    any of them
}
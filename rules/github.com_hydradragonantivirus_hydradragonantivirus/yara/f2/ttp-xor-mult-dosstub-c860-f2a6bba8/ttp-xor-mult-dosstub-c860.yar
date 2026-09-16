rule TTP_XOR_MULT_DOSStub_c860 {
  strings:
    $key_c860 = { 9c 08 [2] e8 10 [2] af 12 [2] e8 03 [2] a6 0f [2] aa 05 [2] bd 0e [2] a6 40 [2] 9b }

  condition:
    any of them
}
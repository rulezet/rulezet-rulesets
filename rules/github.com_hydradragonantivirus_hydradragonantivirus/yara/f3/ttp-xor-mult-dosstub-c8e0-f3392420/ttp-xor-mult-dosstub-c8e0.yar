rule TTP_XOR_MULT_DOSStub_c8e0 {
  strings:
    $key_c8e0 = { 9c 88 [2] e8 90 [2] af 92 [2] e8 83 [2] a6 8f [2] aa 85 [2] bd 8e [2] a6 c0 [2] 9b }

  condition:
    any of them
}
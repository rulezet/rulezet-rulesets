rule TTP_XOR_MULT_DOSStub_c851 {
  strings:
    $key_c851 = { 9c 39 [2] e8 21 [2] af 23 [2] e8 32 [2] a6 3e [2] aa 34 [2] bd 3f [2] a6 71 [2] 9b }

  condition:
    any of them
}
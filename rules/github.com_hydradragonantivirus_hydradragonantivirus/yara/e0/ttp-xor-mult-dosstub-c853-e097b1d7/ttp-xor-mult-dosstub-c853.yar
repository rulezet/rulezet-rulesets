rule TTP_XOR_MULT_DOSStub_c853 {
  strings:
    $key_c853 = { 9c 3b [2] e8 23 [2] af 21 [2] e8 30 [2] a6 3c [2] aa 36 [2] bd 3d [2] a6 73 [2] 9b }

  condition:
    any of them
}
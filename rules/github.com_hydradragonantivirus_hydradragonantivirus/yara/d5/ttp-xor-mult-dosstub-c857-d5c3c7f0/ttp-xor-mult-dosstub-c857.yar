rule TTP_XOR_MULT_DOSStub_c857 {
  strings:
    $key_c857 = { 9c 3f [2] e8 27 [2] af 25 [2] e8 34 [2] a6 38 [2] aa 32 [2] bd 39 [2] a6 77 [2] 9b }

  condition:
    any of them
}
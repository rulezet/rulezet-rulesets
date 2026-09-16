rule TTP_XOR_MULT_DOSStub_c815 {
  strings:
    $key_c815 = { 9c 7d [2] e8 65 [2] af 67 [2] e8 76 [2] a6 7a [2] aa 70 [2] bd 7b [2] a6 35 [2] 9b }

  condition:
    any of them
}
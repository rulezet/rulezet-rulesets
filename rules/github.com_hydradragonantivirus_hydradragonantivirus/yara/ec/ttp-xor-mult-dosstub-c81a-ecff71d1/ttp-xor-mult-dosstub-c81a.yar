rule TTP_XOR_MULT_DOSStub_c81a {
  strings:
    $key_c81a = { 9c 72 [2] e8 6a [2] af 68 [2] e8 79 [2] a6 75 [2] aa 7f [2] bd 74 [2] a6 3a [2] 9b }

  condition:
    any of them
}
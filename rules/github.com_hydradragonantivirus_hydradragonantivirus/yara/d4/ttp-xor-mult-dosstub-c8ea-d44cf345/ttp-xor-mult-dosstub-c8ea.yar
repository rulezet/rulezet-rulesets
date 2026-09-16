rule TTP_XOR_MULT_DOSStub_c8ea {
  strings:
    $key_c8ea = { 9c 82 [2] e8 9a [2] af 98 [2] e8 89 [2] a6 85 [2] aa 8f [2] bd 84 [2] a6 ca [2] 9b }

  condition:
    any of them
}
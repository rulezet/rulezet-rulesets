rule TTP_XOR_MULT_DOSStub_c87c {
  strings:
    $key_c87c = { 9c 14 [2] e8 0c [2] af 0e [2] e8 1f [2] a6 13 [2] aa 19 [2] bd 12 [2] a6 5c [2] 9b }

  condition:
    any of them
}
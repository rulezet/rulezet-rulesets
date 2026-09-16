rule TTP_XOR_MULT_DOSStub_c87b {
  strings:
    $key_c87b = { 9c 13 [2] e8 0b [2] af 09 [2] e8 18 [2] a6 14 [2] aa 1e [2] bd 15 [2] a6 5b [2] 9b }

  condition:
    any of them
}
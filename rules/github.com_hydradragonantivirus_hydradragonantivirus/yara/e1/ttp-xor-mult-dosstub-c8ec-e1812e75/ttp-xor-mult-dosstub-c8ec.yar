rule TTP_XOR_MULT_DOSStub_c8ec {
  strings:
    $key_c8ec = { 9c 84 [2] e8 9c [2] af 9e [2] e8 8f [2] a6 83 [2] aa 89 [2] bd 82 [2] a6 cc [2] 9b }

  condition:
    any of them
}
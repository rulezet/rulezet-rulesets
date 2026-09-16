rule TTP_XOR_MULT_DOSStub_c8fc {
  strings:
    $key_c8fc = { 9c 94 [2] e8 8c [2] af 8e [2] e8 9f [2] a6 93 [2] aa 99 [2] bd 92 [2] a6 dc [2] 9b }

  condition:
    any of them
}
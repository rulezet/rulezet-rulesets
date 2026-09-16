rule TTP_XOR_MULT_DOSStub_c85b {
  strings:
    $key_c85b = { 9c 33 [2] e8 2b [2] af 29 [2] e8 38 [2] a6 34 [2] aa 3e [2] bd 35 [2] a6 7b [2] 9b }

  condition:
    any of them
}
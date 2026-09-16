rule TTP_XOR_MULT_DOSStub_c80d {
  strings:
    $key_c80d = { 9c 65 [2] e8 7d [2] af 7f [2] e8 6e [2] a6 62 [2] aa 68 [2] bd 63 [2] a6 2d [2] 9b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c84d {
  strings:
    $key_c84d = { 9c 25 [2] e8 3d [2] af 3f [2] e8 2e [2] a6 22 [2] aa 28 [2] bd 23 [2] a6 6d [2] 9b }

  condition:
    any of them
}
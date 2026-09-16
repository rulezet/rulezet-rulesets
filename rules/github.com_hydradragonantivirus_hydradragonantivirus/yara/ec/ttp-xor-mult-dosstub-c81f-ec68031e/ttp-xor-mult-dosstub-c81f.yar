rule TTP_XOR_MULT_DOSStub_c81f {
  strings:
    $key_c81f = { 9c 77 [2] e8 6f [2] af 6d [2] e8 7c [2] a6 70 [2] aa 7a [2] bd 71 [2] a6 3f [2] 9b }

  condition:
    any of them
}
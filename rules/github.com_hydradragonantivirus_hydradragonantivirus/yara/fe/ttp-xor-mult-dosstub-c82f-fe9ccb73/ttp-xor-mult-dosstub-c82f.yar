rule TTP_XOR_MULT_DOSStub_c82f {
  strings:
    $key_c82f = { 9c 47 [2] e8 5f [2] af 5d [2] e8 4c [2] a6 40 [2] aa 4a [2] bd 41 [2] a6 0f [2] 9b }

  condition:
    any of them
}
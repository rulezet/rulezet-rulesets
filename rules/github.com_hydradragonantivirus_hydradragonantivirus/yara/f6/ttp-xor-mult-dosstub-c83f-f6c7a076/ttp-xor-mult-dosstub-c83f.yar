rule TTP_XOR_MULT_DOSStub_c83f {
  strings:
    $key_c83f = { 9c 57 [2] e8 4f [2] af 4d [2] e8 5c [2] a6 50 [2] aa 5a [2] bd 51 [2] a6 1f [2] 9b }

  condition:
    any of them
}
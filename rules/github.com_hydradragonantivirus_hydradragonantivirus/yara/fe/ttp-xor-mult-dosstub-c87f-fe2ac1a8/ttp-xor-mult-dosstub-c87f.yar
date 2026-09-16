rule TTP_XOR_MULT_DOSStub_c87f {
  strings:
    $key_c87f = { 9c 17 [2] e8 0f [2] af 0d [2] e8 1c [2] a6 10 [2] aa 1a [2] bd 11 [2] a6 5f [2] 9b }

  condition:
    any of them
}
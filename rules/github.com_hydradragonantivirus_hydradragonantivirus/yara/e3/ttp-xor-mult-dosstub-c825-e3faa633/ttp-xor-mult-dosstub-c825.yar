rule TTP_XOR_MULT_DOSStub_c825 {
  strings:
    $key_c825 = { 9c 4d [2] e8 55 [2] af 57 [2] e8 46 [2] a6 4a [2] aa 40 [2] bd 4b [2] a6 05 [2] 9b }

  condition:
    any of them
}
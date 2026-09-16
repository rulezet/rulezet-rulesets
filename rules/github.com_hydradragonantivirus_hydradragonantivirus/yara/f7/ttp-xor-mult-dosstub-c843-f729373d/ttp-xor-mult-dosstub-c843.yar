rule TTP_XOR_MULT_DOSStub_c843 {
  strings:
    $key_c843 = { 9c 2b [2] e8 33 [2] af 31 [2] e8 20 [2] a6 2c [2] aa 26 [2] bd 2d [2] a6 63 [2] 9b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c832 {
  strings:
    $key_c832 = { 9c 5a [2] e8 42 [2] af 40 [2] e8 51 [2] a6 5d [2] aa 57 [2] bd 5c [2] a6 12 [2] 9b }

  condition:
    any of them
}
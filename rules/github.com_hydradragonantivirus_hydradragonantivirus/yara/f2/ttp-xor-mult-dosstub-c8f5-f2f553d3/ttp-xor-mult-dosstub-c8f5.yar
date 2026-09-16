rule TTP_XOR_MULT_DOSStub_c8f5 {
  strings:
    $key_c8f5 = { 9c 9d [2] e8 85 [2] af 87 [2] e8 96 [2] a6 9a [2] aa 90 [2] bd 9b [2] a6 d5 [2] 9b }

  condition:
    any of them
}
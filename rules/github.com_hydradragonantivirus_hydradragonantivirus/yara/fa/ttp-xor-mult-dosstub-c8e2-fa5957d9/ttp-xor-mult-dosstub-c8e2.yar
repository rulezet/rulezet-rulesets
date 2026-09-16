rule TTP_XOR_MULT_DOSStub_c8e2 {
  strings:
    $key_c8e2 = { 9c 8a [2] e8 92 [2] af 90 [2] e8 81 [2] a6 8d [2] aa 87 [2] bd 8c [2] a6 c2 [2] 9b }

  condition:
    any of them
}
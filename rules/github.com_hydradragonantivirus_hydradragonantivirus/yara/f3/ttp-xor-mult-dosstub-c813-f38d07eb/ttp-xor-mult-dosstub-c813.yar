rule TTP_XOR_MULT_DOSStub_c813 {
  strings:
    $key_c813 = { 9c 7b [2] e8 63 [2] af 61 [2] e8 70 [2] a6 7c [2] aa 76 [2] bd 7d [2] a6 33 [2] 9b }

  condition:
    any of them
}
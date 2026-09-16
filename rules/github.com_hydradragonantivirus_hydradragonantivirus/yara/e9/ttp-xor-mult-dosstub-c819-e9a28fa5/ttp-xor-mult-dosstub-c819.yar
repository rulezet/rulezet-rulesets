rule TTP_XOR_MULT_DOSStub_c819 {
  strings:
    $key_c819 = { 9c 71 [2] e8 69 [2] af 6b [2] e8 7a [2] a6 76 [2] aa 7c [2] bd 77 [2] a6 39 [2] 9b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c8f9 {
  strings:
    $key_c8f9 = { 9c 91 [2] e8 89 [2] af 8b [2] e8 9a [2] a6 96 [2] aa 9c [2] bd 97 [2] a6 d9 [2] 9b }

  condition:
    any of them
}
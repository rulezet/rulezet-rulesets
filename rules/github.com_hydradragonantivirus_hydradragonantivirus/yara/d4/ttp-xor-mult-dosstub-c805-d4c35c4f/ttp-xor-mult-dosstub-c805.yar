rule TTP_XOR_MULT_DOSStub_c805 {
  strings:
    $key_c805 = { 9c 6d [2] e8 75 [2] af 77 [2] e8 66 [2] a6 6a [2] aa 60 [2] bd 6b [2] a6 25 [2] 9b }

  condition:
    any of them
}
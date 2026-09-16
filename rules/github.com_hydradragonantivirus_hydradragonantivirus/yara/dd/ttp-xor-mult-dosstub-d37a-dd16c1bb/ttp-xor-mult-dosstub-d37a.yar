rule TTP_XOR_MULT_DOSStub_d37a {
  strings:
    $key_d37a = { 87 12 [2] f3 0a [2] b4 08 [2] f3 19 [2] bd 15 [2] b1 1f [2] a6 14 [2] bd 5a [2] 80 }

  condition:
    any of them
}
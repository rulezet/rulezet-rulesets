rule TTP_XOR_MULT_DOSStub_d321 {
  strings:
    $key_d321 = { 87 49 [2] f3 51 [2] b4 53 [2] f3 42 [2] bd 4e [2] b1 44 [2] a6 4f [2] bd 01 [2] 80 }

  condition:
    any of them
}
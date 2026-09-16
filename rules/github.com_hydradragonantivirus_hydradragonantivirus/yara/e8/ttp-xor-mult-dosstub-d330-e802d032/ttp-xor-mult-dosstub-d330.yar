rule TTP_XOR_MULT_DOSStub_d330 {
  strings:
    $key_d330 = { 87 58 [2] f3 40 [2] b4 42 [2] f3 53 [2] bd 5f [2] b1 55 [2] a6 5e [2] bd 10 [2] 80 }

  condition:
    any of them
}
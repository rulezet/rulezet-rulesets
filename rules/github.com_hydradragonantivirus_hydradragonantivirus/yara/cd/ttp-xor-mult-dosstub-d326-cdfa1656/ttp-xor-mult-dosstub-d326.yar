rule TTP_XOR_MULT_DOSStub_d326 {
  strings:
    $key_d326 = { 87 4e [2] f3 56 [2] b4 54 [2] f3 45 [2] bd 49 [2] b1 43 [2] a6 48 [2] bd 06 [2] 80 }

  condition:
    any of them
}
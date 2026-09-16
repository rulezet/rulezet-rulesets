rule TTP_XOR_MULT_DOSStub_d3e7 {
  strings:
    $key_d3e7 = { 87 8f [2] f3 97 [2] b4 95 [2] f3 84 [2] bd 88 [2] b1 82 [2] a6 89 [2] bd c7 [2] 80 }

  condition:
    any of them
}
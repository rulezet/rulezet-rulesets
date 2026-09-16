rule TTP_XOR_MULT_DOSStub_d760 {
  strings:
    $key_d760 = { 83 08 [2] f7 10 [2] b0 12 [2] f7 03 [2] b9 0f [2] b5 05 [2] a2 0e [2] b9 40 [2] 84 }

  condition:
    any of them
}
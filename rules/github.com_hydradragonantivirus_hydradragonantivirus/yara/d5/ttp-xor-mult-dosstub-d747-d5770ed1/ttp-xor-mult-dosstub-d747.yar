rule TTP_XOR_MULT_DOSStub_d747 {
  strings:
    $key_d747 = { 83 2f [2] f7 37 [2] b0 35 [2] f7 24 [2] b9 28 [2] b5 22 [2] a2 29 [2] b9 67 [2] 84 }

  condition:
    any of them
}
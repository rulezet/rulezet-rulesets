rule TTP_XOR_MULT_DOSStub_d731 {
  strings:
    $key_d731 = { 83 59 [2] f7 41 [2] b0 43 [2] f7 52 [2] b9 5e [2] b5 54 [2] a2 5f [2] b9 11 [2] 84 }

  condition:
    any of them
}
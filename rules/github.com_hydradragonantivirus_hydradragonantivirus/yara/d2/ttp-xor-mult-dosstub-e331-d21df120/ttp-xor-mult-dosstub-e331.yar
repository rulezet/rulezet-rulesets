rule TTP_XOR_MULT_DOSStub_e331 {
  strings:
    $key_e331 = { b7 59 [2] c3 41 [2] 84 43 [2] c3 52 [2] 8d 5e [2] 81 54 [2] 96 5f [2] 8d 11 [2] b0 }

  condition:
    any of them
}
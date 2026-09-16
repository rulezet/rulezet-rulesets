rule TTP_XOR_MULT_DOSStub_c137 {
  strings:
    $key_c137 = { 95 5f [2] e1 47 [2] a6 45 [2] e1 54 [2] af 58 [2] a3 52 [2] b4 59 [2] af 17 [2] 92 }

  condition:
    any of them
}
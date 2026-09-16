rule TTP_XOR_MULT_DOSStub_f137 {
  strings:
    $key_f137 = { a5 5f [2] d1 47 [2] 96 45 [2] d1 54 [2] 9f 58 [2] 93 52 [2] 84 59 [2] 9f 17 [2] a2 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e220 {
  strings:
    $key_e220 = { b6 48 [2] c2 50 [2] 85 52 [2] c2 43 [2] 8c 4f [2] 80 45 [2] 97 4e [2] 8c 00 [2] b1 }

  condition:
    any of them
}
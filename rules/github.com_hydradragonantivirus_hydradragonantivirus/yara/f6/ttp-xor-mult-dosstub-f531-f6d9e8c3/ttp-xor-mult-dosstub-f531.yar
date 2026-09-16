rule TTP_XOR_MULT_DOSStub_f531 {
  strings:
    $key_f531 = { a1 59 [2] d5 41 [2] 92 43 [2] d5 52 [2] 9b 5e [2] 97 54 [2] 80 5f [2] 9b 11 [2] a6 }

  condition:
    any of them
}
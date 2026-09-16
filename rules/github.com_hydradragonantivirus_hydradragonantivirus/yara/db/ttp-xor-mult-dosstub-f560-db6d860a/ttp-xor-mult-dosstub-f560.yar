rule TTP_XOR_MULT_DOSStub_f560 {
  strings:
    $key_f560 = { a1 08 [2] d5 10 [2] 92 12 [2] d5 03 [2] 9b 0f [2] 97 05 [2] 80 0e [2] 9b 40 [2] a6 }

  condition:
    any of them
}
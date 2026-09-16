rule TTP_XOR_MULT_DOSStub_f5e0 {
  strings:
    $key_f5e0 = { a1 88 [2] d5 90 [2] 92 92 [2] d5 83 [2] 9b 8f [2] 97 85 [2] 80 8e [2] 9b c0 [2] a6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f565 {
  strings:
    $key_f565 = { a1 0d [2] d5 15 [2] 92 17 [2] d5 06 [2] 9b 0a [2] 97 00 [2] 80 0b [2] 9b 45 [2] a6 }

  condition:
    any of them
}
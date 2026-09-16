rule TTP_XOR_MULT_DOSStub_f50a {
  strings:
    $key_f50a = { a1 62 [2] d5 7a [2] 92 78 [2] d5 69 [2] 9b 65 [2] 97 6f [2] 80 64 [2] 9b 2a [2] a6 }

  condition:
    any of them
}
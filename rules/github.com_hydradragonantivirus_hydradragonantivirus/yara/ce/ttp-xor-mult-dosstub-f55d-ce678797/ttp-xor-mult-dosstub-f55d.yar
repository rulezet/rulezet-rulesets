rule TTP_XOR_MULT_DOSStub_f55d {
  strings:
    $key_f55d = { a1 35 [2] d5 2d [2] 92 2f [2] d5 3e [2] 9b 32 [2] 97 38 [2] 80 33 [2] 9b 7d [2] a6 }

  condition:
    any of them
}
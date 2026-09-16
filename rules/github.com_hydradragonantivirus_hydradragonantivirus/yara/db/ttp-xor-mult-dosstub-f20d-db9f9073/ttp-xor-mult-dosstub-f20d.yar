rule TTP_XOR_MULT_DOSStub_f20d {
  strings:
    $key_f20d = { a6 65 [2] d2 7d [2] 95 7f [2] d2 6e [2] 9c 62 [2] 90 68 [2] 87 63 [2] 9c 2d [2] a1 }

  condition:
    any of them
}
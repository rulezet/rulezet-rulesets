rule TTP_XOR_MULT_DOSStub_e20d {
  strings:
    $key_e20d = { b6 65 [2] c2 7d [2] 85 7f [2] c2 6e [2] 8c 62 [2] 80 68 [2] 97 63 [2] 8c 2d [2] b1 }

  condition:
    any of them
}
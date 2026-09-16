rule TTP_XOR_MULT_DOSStub_b70d {
  strings:
    $key_b70d = { e3 65 [2] 97 7d [2] d0 7f [2] 97 6e [2] d9 62 [2] d5 68 [2] c2 63 [2] d9 2d [2] e4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c62d {
  strings:
    $key_c62d = { 92 45 [2] e6 5d [2] a1 5f [2] e6 4e [2] a8 42 [2] a4 48 [2] b3 43 [2] a8 0d [2] 95 }

  condition:
    any of them
}
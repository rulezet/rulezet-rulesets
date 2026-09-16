rule TTP_XOR_MULT_DOSStub_c63d {
  strings:
    $key_c63d = { 92 55 [2] e6 4d [2] a1 4f [2] e6 5e [2] a8 52 [2] a4 58 [2] b3 53 [2] a8 1d [2] 95 }

  condition:
    any of them
}
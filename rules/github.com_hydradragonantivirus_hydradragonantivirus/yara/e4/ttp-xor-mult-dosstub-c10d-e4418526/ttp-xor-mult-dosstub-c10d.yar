rule TTP_XOR_MULT_DOSStub_c10d {
  strings:
    $key_c10d = { 95 65 [2] e1 7d [2] a6 7f [2] e1 6e [2] af 62 [2] a3 68 [2] b4 63 [2] af 2d [2] 92 }

  condition:
    any of them
}
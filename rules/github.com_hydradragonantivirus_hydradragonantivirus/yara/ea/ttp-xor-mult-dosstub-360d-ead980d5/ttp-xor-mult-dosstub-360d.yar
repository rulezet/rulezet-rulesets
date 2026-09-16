rule TTP_XOR_MULT_DOSStub_360d {
  strings:
    $key_360d = { 62 65 [2] 16 7d [2] 51 7f [2] 16 6e [2] 58 62 [2] 54 68 [2] 43 63 [2] 58 2d [2] 65 }

  condition:
    any of them
}
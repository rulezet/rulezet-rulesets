rule TTP_XOR_MULT_DOSStub_410d {
  strings:
    $key_410d = { 15 65 [2] 61 7d [2] 26 7f [2] 61 6e [2] 2f 62 [2] 23 68 [2] 34 63 [2] 2f 2d [2] 12 }

  condition:
    any of them
}
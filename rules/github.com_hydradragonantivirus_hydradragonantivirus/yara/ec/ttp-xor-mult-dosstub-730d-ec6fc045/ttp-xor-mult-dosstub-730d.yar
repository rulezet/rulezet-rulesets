rule TTP_XOR_MULT_DOSStub_730d {
  strings:
    $key_730d = { 27 65 [2] 53 7d [2] 14 7f [2] 53 6e [2] 1d 62 [2] 11 68 [2] 06 63 [2] 1d 2d [2] 20 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_680d {
  strings:
    $key_680d = { 3c 65 [2] 48 7d [2] 0f 7f [2] 48 6e [2] 06 62 [2] 0a 68 [2] 1d 63 [2] 06 2d [2] 3b }

  condition:
    any of them
}
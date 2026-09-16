rule TTP_XOR_MULT_DOSStub_1b0d {
  strings:
    $key_1b0d = { 4f 65 [2] 3b 7d [2] 7c 7f [2] 3b 6e [2] 75 62 [2] 79 68 [2] 6e 63 [2] 75 2d [2] 48 }

  condition:
    any of them
}
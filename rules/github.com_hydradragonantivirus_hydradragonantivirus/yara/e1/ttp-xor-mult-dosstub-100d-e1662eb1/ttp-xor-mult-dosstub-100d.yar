rule TTP_XOR_MULT_DOSStub_100d {
  strings:
    $key_100d = { 44 65 [2] 30 7d [2] 77 7f [2] 30 6e [2] 7e 62 [2] 72 68 [2] 65 63 [2] 7e 2d [2] 43 }

  condition:
    any of them
}
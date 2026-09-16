rule TTP_XOR_MULT_DOSStub_300d {
  strings:
    $key_300d = { 64 65 [2] 10 7d [2] 57 7f [2] 10 6e [2] 5e 62 [2] 52 68 [2] 45 63 [2] 5e 2d [2] 63 }

  condition:
    any of them
}
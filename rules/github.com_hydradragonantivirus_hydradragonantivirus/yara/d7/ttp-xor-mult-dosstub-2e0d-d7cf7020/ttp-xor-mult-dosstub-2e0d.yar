rule TTP_XOR_MULT_DOSStub_2e0d {
  strings:
    $key_2e0d = { 7a 65 [2] 0e 7d [2] 49 7f [2] 0e 6e [2] 40 62 [2] 4c 68 [2] 5b 63 [2] 40 2d [2] 7d }

  condition:
    any of them
}
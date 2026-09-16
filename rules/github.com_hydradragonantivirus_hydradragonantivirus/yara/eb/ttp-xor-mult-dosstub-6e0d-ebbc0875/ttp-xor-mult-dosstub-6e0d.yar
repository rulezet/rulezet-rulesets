rule TTP_XOR_MULT_DOSStub_6e0d {
  strings:
    $key_6e0d = { 3a 65 [2] 4e 7d [2] 09 7f [2] 4e 6e [2] 00 62 [2] 0c 68 [2] 1b 63 [2] 00 2d [2] 3d }

  condition:
    any of them
}
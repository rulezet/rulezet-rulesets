rule TTP_XOR_MULT_DOSStub_690d {
  strings:
    $key_690d = { 3d 65 [2] 49 7d [2] 0e 7f [2] 49 6e [2] 07 62 [2] 0b 68 [2] 1c 63 [2] 07 2d [2] 3a }

  condition:
    any of them
}
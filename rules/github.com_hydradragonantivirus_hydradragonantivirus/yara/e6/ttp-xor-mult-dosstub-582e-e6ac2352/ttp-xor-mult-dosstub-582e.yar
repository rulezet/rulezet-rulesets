rule TTP_XOR_MULT_DOSStub_582e {
  strings:
    $key_582e = { 0c 46 [2] 78 5e [2] 3f 5c [2] 78 4d [2] 36 41 [2] 3a 4b [2] 2d 40 [2] 36 0e [2] 0b }

  condition:
    any of them
}
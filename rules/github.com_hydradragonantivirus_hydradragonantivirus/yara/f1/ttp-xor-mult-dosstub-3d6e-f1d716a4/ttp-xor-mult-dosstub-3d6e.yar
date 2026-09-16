rule TTP_XOR_MULT_DOSStub_3d6e {
  strings:
    $key_3d6e = { 69 06 [2] 1d 1e [2] 5a 1c [2] 1d 0d [2] 53 01 [2] 5f 0b [2] 48 00 [2] 53 4e [2] 6e }

  condition:
    any of them
}
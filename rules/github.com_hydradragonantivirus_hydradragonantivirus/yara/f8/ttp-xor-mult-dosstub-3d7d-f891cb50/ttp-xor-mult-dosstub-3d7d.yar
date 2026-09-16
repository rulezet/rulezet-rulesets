rule TTP_XOR_MULT_DOSStub_3d7d {
  strings:
    $key_3d7d = { 69 15 [2] 1d 0d [2] 5a 0f [2] 1d 1e [2] 53 12 [2] 5f 18 [2] 48 13 [2] 53 5d [2] 6e }

  condition:
    any of them
}